#include <gtest/gtest.h>
#include "meshlink/connection.h"
#include "meshlink/errors.h"

#include <array>
#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

using namespace invilite::Mesh;
using namespace std::chrono_literals;

namespace {

uint16_t crc16(const uint8_t* data, size_t length);

// Two Connections over a real loopback TCP socket pair with a completed transport handshake.
// Raw fds stay accessible so tests can inject arbitrary bytes on the wire.
class EstablishedConnectionPair : public ::testing::Test {
protected:
    void SetUp() override {
        secret.fill(0x5A);

        const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
        ASSERT_GE(listener, 0);
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ASSERT_EQ(::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
        ASSERT_EQ(::listen(listener, 1), 0);
        socklen_t addrLen = sizeof(addr);
        ASSERT_EQ(::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &addrLen), 0);

        clientFd = ::socket(AF_INET, SOCK_STREAM, 0);
        ASSERT_EQ(::connect(clientFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
        sockaddr_storage peerAddr{};
        socklen_t peerAddrLen = sizeof(peerAddr);
        serverFd = ::accept(listener, reinterpret_cast<sockaddr*>(&peerAddr), &peerAddrLen);
        ASSERT_GE(serverFd, 0);
        ::close(listener);

        sockaddr_storage clientView{};
        std::memcpy(&clientView, &addr, sizeof(addr));
        client = std::make_unique<Connection>(clientFd, &clientView, &secret);
        server = std::make_unique<Connection>(serverFd, &peerAddr, &secret);

        ASSERT_EQ(client->initHandshake(), 0);
        ASSERT_GT(server->waitForHandshake(2000ms), 0);                                       // responder: > 0
        ASSERT_EQ(client->waitForHandshake(2000ms), 0);                                       // initiator: == 0
    }

    void TearDown() override {
        if (client) client->close();
        if (server) server->close();
    }

    // Read exactly `length` raw bytes from the server-side socket, bypassing Connection.
    std::vector<uint8_t> readRawFromServerSocket(size_t length) {
        std::vector<uint8_t> out;
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (out.size() < length && std::chrono::steady_clock::now() < deadline) {
            uint8_t chunk[4096];
            const ssize_t n = ::recv(serverFd, chunk, std::min(sizeof(chunk), length - out.size()), 0);
            if (n > 0) out.insert(out.end(), chunk, chunk + n);
        }
        return out;
    }

    void writeRawFromClientSocket(const std::vector<uint8_t>& bytes) {
        ASSERT_EQ(::send(clientFd, bytes.data(), bytes.size(), 0), static_cast<ssize_t>(bytes.size()));
    }

    std::array<uint8_t, 64>     secret{};
    int                         clientFd = -1;
    int                         serverFd = -1;
    std::unique_ptr<Connection> client;
    std::unique_ptr<Connection> server;
};

// CRC16 as used by the frame header (CCITT polynomial 0x1021, non-reflected, custom init 0x16AB — see crc16Table
// in connection.cpp). Recomputed here so a test can forge a header with a valid checksum.
uint16_t crc16(const uint8_t* data, size_t length) {
    uint16_t crc = 0x16AB;
    for (size_t i = 0; i < length; ++i) {
        crc ^= static_cast<uint16_t>(data[i]) << 8;
        for (int bit = 0; bit < 8; ++bit) crc = (crc & 0x8000) ? static_cast<uint16_t>((crc << 1) ^ 0x1021) : static_cast<uint16_t>(crc << 1);
    }
    return crc;
}

constexpr size_t NONCE_SIZE  = 24;
constexpr size_t HEADER_SIZE = 8;
constexpr size_t TAG_SIZE    = 16;

std::array<uint8_t, HEADER_SIZE> plainHeader(uint32_t frameLength) {
    std::array<uint8_t, HEADER_SIZE> header{ 0x01, 0x00, static_cast<uint8_t>(frameLength >> 24), static_cast<uint8_t>(frameLength >> 16), static_cast<uint8_t>(frameLength >> 8), static_cast<uint8_t>(frameLength) };
    const uint16_t crc = crc16(header.data(), 6);
    header[6] = static_cast<uint8_t>(crc >> 8);
    header[7] = static_cast<uint8_t>(crc);
    return header;
}

} // namespace

TEST_F(EstablishedConnectionPair, DeliversFrameSentByPeer) {
    const std::vector<uint8_t> payload = { 1, 2, 3, 4, 5 };
    ASSERT_GT(client->send(&payload), 0);

    std::vector<uint8_t> received;
    ssize_t result = 0;
    for (int attempt = 0; attempt < 20 && result == 0; ++attempt) result = server->receive(received, 100ms);

    ASSERT_GT(result, 0);
    EXPECT_EQ(received, payload);
}

// Guards the forging technique used by the B5 test: change only the flags byte of a genuine header (same length).
// If our plaintext-header reconstruction were wrong, the forged CRC would not match and the header would be rejected
// (InvalidFrameHeader). A correct forgery passes header validation and fails only at AEAD authentication.
TEST_F(EstablishedConnectionPair, ForgedHeaderPassesHeaderValidation) {
    const std::vector<uint8_t> payload(8, 0xAB);
    ASSERT_GT(client->send(&payload), 0);
    auto frame = readRawFromServerSocket(NONCE_SIZE + HEADER_SIZE + payload.size() + TAG_SIZE);
    ASSERT_EQ(frame.size(), NONCE_SIZE + HEADER_SIZE + payload.size() + TAG_SIZE);

    const auto genuine = plainHeader(static_cast<uint32_t>(frame.size()));
    auto forged = genuine;
    forged[1] = 0x01;                                                                         // flags
    const uint16_t crc = crc16(forged.data(), 6);
    forged[6] = static_cast<uint8_t>(crc >> 8);
    forged[7] = static_cast<uint8_t>(crc);
    for (size_t i = 0; i < HEADER_SIZE; ++i) frame[NONCE_SIZE + i] = static_cast<uint8_t>(frame[NONCE_SIZE + i] ^ genuine[i] ^ forged[i]);
    writeRawFromClientSocket(frame);

    std::vector<uint8_t> received;
    ssize_t result = 0;
    for (int attempt = 0; attempt < 20 && result == 0; ++attempt) result = server->receive(received, 100ms);

    EXPECT_EQ(result, static_cast<ssize_t>(Error::Connection::DecryptionError));
}

// B5: a header declaring a frame shorter than nonce + header + tag (48 B) must be rejected as an invalid header.
// Before the fix, decryptData built a negative byte range from such a frame (undefined behavior).
TEST_F(EstablishedConnectionPair, RejectsFrameShorterThanMinimumFrameSize) {
    const std::vector<uint8_t> payload(8, 0xCD);
    ASSERT_GT(client->send(&payload), 0);
    auto frame = readRawFromServerSocket(NONCE_SIZE + HEADER_SIZE + payload.size() + TAG_SIZE);
    ASSERT_EQ(frame.size(), NONCE_SIZE + HEADER_SIZE + payload.size() + TAG_SIZE);

    // Recover the header mask for this nonce from the known plaintext header, then forge a header claiming 10 bytes.
    const auto genuine = plainHeader(static_cast<uint32_t>(frame.size()));
    const auto forged  = plainHeader(10);
    for (size_t i = 0; i < HEADER_SIZE; ++i) frame[NONCE_SIZE + i] = static_cast<uint8_t>(frame[NONCE_SIZE + i] ^ genuine[i] ^ forged[i]);
    writeRawFromClientSocket(frame);

    std::vector<uint8_t> received;
    ssize_t result = 0;
    for (int attempt = 0; attempt < 20 && result == 0; ++attempt) result = server->receive(received, 100ms);

    EXPECT_EQ(result, static_cast<ssize_t>(Error::Connection::InvalidFrameHeader));
}

// A Connection owns its socket: destroying it without an explicit close() must not leak the descriptor.
TEST_F(EstablishedConnectionPair, DestructorClosesSocket) {
    const int fd = clientFd;
    client.reset();

    errno = 0;
    EXPECT_EQ(::fcntl(fd, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
}
