#include <gtest/gtest.h>
#include "meshlink/connection.h"
#include "meshlink/errors.h"
#include "meshlink/peer.h"

#include <array>
#include <atomic>
#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

using namespace invilite::Mesh;
using namespace std::chrono_literals;

namespace {

uint16_t crc16(const uint8_t* data, size_t length);

// Two Connections over a real loopback TCP socket pair with a completed transport handshake.
// Raw fds stay accessible so tests can inject arbitrary bytes on the wire.
// Socket buffers are shrunk so a test can fill them with a few frames: without that, loopback autotuning absorbs
// megabytes and the send queue would never be exercised.
class EstablishedConnectionPair : public ::testing::Test {
protected:
    void SetUp() override {
        secret.fill(0x5A);

        const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
        ASSERT_GE(listener, 0);
        setSmallSocketBuffers(listener);                                                       // inherited by the accepted socket
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ASSERT_EQ(::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
        ASSERT_EQ(::listen(listener, 1), 0);
        socklen_t addrLen = sizeof(addr);
        ASSERT_EQ(::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &addrLen), 0);

        clientFd = ::socket(AF_INET, SOCK_STREAM, 0);
        setSmallSocketBuffers(clientFd);
        ASSERT_EQ(::connect(clientFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
        sockaddr_storage peerAddr{};
        socklen_t peerAddrLen = sizeof(peerAddr);
        serverFd = ::accept(listener, reinterpret_cast<sockaddr*>(&peerAddr), &peerAddrLen);
        ASSERT_GE(serverFd, 0);
        ::close(listener);

        sockaddr_storage clientView{};
        std::memcpy(&clientView, &addr, sizeof(addr));
        client = std::make_shared<Connection>(clientFd, &clientView, &secret, clientSendQueueLimit);
        server = std::make_shared<Connection>(serverFd, &peerAddr, &secret);

        ASSERT_EQ(client->initHandshake(), 0);
        ASSERT_GT(server->waitForHandshake(2000ms), 0);                                       // responder: > 0
        ASSERT_EQ(client->waitForHandshake(2000ms), 0);                                       // initiator: == 0
    }

    void TearDown() override {
        if (client) client->close();
        if (server) server->close();
    }

    static void setSmallSocketBuffers(int fd) {
        const int size = 4096;
        ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
        ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    }

    // Read exactly `length` raw bytes from the server-side socket, bypassing Connection.
    std::vector<uint8_t> readRawFromServerSocket(size_t length) {
        std::vector<uint8_t> out;
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (out.size() < length && std::chrono::steady_clock::now() < deadline) {
            pollfd pfd{ serverFd, POLLIN, 0 };
            if (::poll(&pfd, 1, 50) <= 0) continue;                                           // wait for data instead of spinning on EAGAIN
            uint8_t chunk[4096];
            const ssize_t n = ::recv(serverFd, chunk, std::min(sizeof(chunk), length - out.size()), 0);
            if (n > 0) out.insert(out.end(), chunk, chunk + n);
        }
        return out;
    }

    // Sends numbered frames without reading on the other side until part of a frame is left in the send queue.
    // Returns how many frames were accepted.
    uint32_t sendUntilQueued(size_t payloadSize) {
        uint32_t sent = 0;
        while (!client->hasQueuedFrames() && sent < 10000) {
            const auto payload = numberedPayload(sent, payloadSize);
            if (client->send(&payload) <= 0) break;
            ++sent;
        }
        return sent;
    }

    // Moves data both ways — client flushes its queue, server decrypts — until `count` frames arrived or 5 s passed.
    // Stops at the first receive error: a torn or reordered frame shows up as a decryption/header failure.
    std::vector<std::vector<uint8_t>> pumpUntilReceived(size_t count) {
        std::vector<std::vector<uint8_t>> received;
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (received.size() < count && std::chrono::steady_clock::now() < deadline) {
            if (client->writeQueuedFrames() < 0) break;
            std::vector<uint8_t> message;
            const ssize_t n = server->receive(message, 10ms);
            if (n < 0) { ADD_FAILURE() << "receive failed with " << n; break; }
            if (n > 0) received.push_back(std::move(message));
        }
        return received;
    }

    // Payload whose every byte depends on its sequence number — any torn, shifted or swapped frame fails comparison.
    static std::vector<uint8_t> numberedPayload(uint32_t sequence, size_t size) {
        std::vector<uint8_t> payload(size);
        for (size_t i = 0; i < size; ++i) payload[i] = static_cast<uint8_t>(sequence * 131 + i * 7);
        if (size >= 4) std::memcpy(payload.data(), &sequence, 4);
        return payload;
    }

    void writeRawFromClientSocket(const std::vector<uint8_t>& bytes) {
        ASSERT_EQ(::send(clientFd, bytes.data(), bytes.size(), 0), static_cast<ssize_t>(bytes.size()));
    }

    std::array<uint8_t, 64>     secret{};
    size_t                      clientSendQueueLimit = Connection::defaultSendQueueLimit;
    int                         clientFd = -1;
    int                         serverFd = -1;
    std::shared_ptr<Connection> client;
    std::shared_ptr<Connection> server;
};

// Same pair with a small client send queue, so the limit is reached with a handful of frames.
class SmallSendQueuePair : public EstablishedConnectionPair {
protected:
    static constexpr size_t QUEUE_LIMIT = 64 * 1024;
    SmallSendQueuePair() { clientSendQueueLimit = QUEUE_LIMIT; }
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

// B6: receive() reports errors but never closes the socket itself. Closing belongs to the owner (Peer/Network),
// which serializes it with in-flight sends; a self-close on the I/O thread raced with Peer::send on another thread.
TEST_F(EstablishedConnectionPair, ReceiveErrorLeavesClosingToTheOwner) {
    const std::vector<uint8_t> payload(8, 0xEE);
    ASSERT_GT(client->send(&payload), 0);
    auto frame = readRawFromServerSocket(NONCE_SIZE + HEADER_SIZE + payload.size() + TAG_SIZE);
    ASSERT_EQ(frame.size(), NONCE_SIZE + HEADER_SIZE + payload.size() + TAG_SIZE);
    frame.back() ^= 0x01;                                                                     // break the Poly1305 tag
    writeRawFromClientSocket(frame);

    std::vector<uint8_t> received;
    ssize_t result = 0;
    for (int attempt = 0; attempt < 20 && result == 0; ++attempt) result = server->receive(received, 100ms);

    ASSERT_EQ(result, static_cast<ssize_t>(Error::Connection::DecryptionError));
    EXPECT_NE(server->getSocket(), -1);
    EXPECT_NE(::fcntl(serverFd, F_GETFD), -1);
}

TEST_F(EstablishedConnectionPair, ReceiveReportsRemoteCloseWithoutClosingSocket) {
    client->close();

    std::vector<uint8_t> received;
    ssize_t result = 0;
    for (int attempt = 0; attempt < 20 && result == 0; ++attempt) result = server->receive(received, 100ms);

    EXPECT_EQ(result, static_cast<ssize_t>(Error::Connection::SocketClosed));
    EXPECT_NE(server->getSocket(), -1);
}

// ===== Receive path — frame sizes beyond the trivial =====

// A frame larger than one socket read (16 KB chunk) and the receive buffer's initial size must be reassembled from many
// reads; several small frames arriving in one read must be split. Both are the normal shape of real traffic.
TEST_F(EstablishedConnectionPair, ReassemblesLargeFramesAndSplitsCoalescedSmallOnes) {
    const std::vector<std::vector<uint8_t>> expected = { numberedPayload(0, 200 * 1024), numberedPayload(1, 3), numberedPayload(2, 17), numberedPayload(3, 40 * 1024) };
    for (const auto& payload : expected) ASSERT_GT(client->send(&payload), 0);

    EXPECT_EQ(pumpUntilReceived(expected.size()), expected);
}

// A header declaring a frame above the 16 MB hard limit cannot be buffered — the stream is unrecoverable and must be
// reported as such instead of growing the receive buffer.
TEST_F(EstablishedConnectionPair, RejectsFrameAboveHardLimit) {
    const std::vector<uint8_t> payload(8, 0x11);
    ASSERT_GT(client->send(&payload), 0);
    auto frame = readRawFromServerSocket(NONCE_SIZE + HEADER_SIZE + payload.size() + TAG_SIZE);
    ASSERT_EQ(frame.size(), NONCE_SIZE + HEADER_SIZE + payload.size() + TAG_SIZE);

    const auto genuine = plainHeader(static_cast<uint32_t>(frame.size()));
    const auto forged  = plainHeader(16777216 + 1);
    for (size_t i = 0; i < HEADER_SIZE; ++i) frame[NONCE_SIZE + i] = static_cast<uint8_t>(frame[NONCE_SIZE + i] ^ genuine[i] ^ forged[i]);
    writeRawFromClientSocket(frame);

    std::vector<uint8_t> received;
    ssize_t result = 0;
    for (int attempt = 0; attempt < 20 && result == 0; ++attempt) result = server->receive(received, 100ms);

    EXPECT_EQ(result, static_cast<ssize_t>(Error::Connection::ReceivedTooMuch));
}

// ===== Send queue (B7) =====

// The common case must cost nothing extra: with an empty queue and room in the socket the frame goes straight out,
// so the owner never has to wake the I/O thread.
TEST_F(EstablishedConnectionPair, SendWritesStraightToSocketWhenNothingIsQueued) {
    const std::vector<uint8_t> payload(100, 0x42);
    ASSERT_EQ(client->send(&payload), static_cast<ssize_t>(payload.size()));

    EXPECT_FALSE(client->hasQueuedFrames());
    EXPECT_EQ(client->getQueuedSendBytes(), 0u);
    EXPECT_EQ(readRawFromServerSocket(NONCE_SIZE + HEADER_SIZE + payload.size() + TAG_SIZE).size(), NONCE_SIZE + HEADER_SIZE + payload.size() + TAG_SIZE);
}

// The B7 bug: a send interrupted mid-frame left half a frame on the wire and the next frame was glued to it.
// Now a frame the socket cannot take is queued instead (send still succeeds), and every frame — including the one
// split between socket and queue — reaches the other side whole and in order.
TEST_F(EstablishedConnectionPair, QueuedFramesArriveWholeAndInOrder) {
    const uint32_t sent = sendUntilQueued(16 * 1024);
    ASSERT_TRUE(client->hasQueuedFrames()) << "socket buffers never filled";

    // Frames sent behind the queue must not overtake it
    for (uint32_t i = 0; i < 3; ++i) {
        const auto payload = numberedPayload(sent + i, 5000);
        ASSERT_GT(client->send(&payload), 0);
    }

    const auto received = pumpUntilReceived(sent + 3);
    ASSERT_EQ(received.size(), sent + 3);
    for (uint32_t i = 0; i < sent; ++i) EXPECT_EQ(received[i], numberedPayload(i, 16 * 1024)) << "frame " << i;
    for (uint32_t i = 0; i < 3; ++i)    EXPECT_EQ(received[sent + i], numberedPayload(sent + i, 5000)) << "frame " << sent + i;
    EXPECT_FALSE(client->hasQueuedFrames());
}

// The queue is bounded: memory held for a peer that does not read never exceeds the limit. A rejected frame is dropped
// whole — nothing of it reaches the wire — so the frames accepted before and after it still arrive intact.
TEST_F(SmallSendQueuePair, FullQueueRejectsFrameWithoutCorruptingStream) {
    uint32_t accepted = 0;
    ssize_t  result   = 0;
    while (accepted < 1000) {
        const auto payload = numberedPayload(accepted, 8 * 1024);
        result = client->send(&payload);
        if (result <= 0) break;
        ++accepted;
    }

    ASSERT_EQ(result, static_cast<ssize_t>(Error::Connection::SendQueueFull));
    EXPECT_LE(client->getQueuedSendBytes(), QUEUE_LIMIT);
    EXPECT_GT(client->getQueuedSendBytes(), QUEUE_LIMIT - (8 * 1024 + NONCE_SIZE + HEADER_SIZE + TAG_SIZE));   // full, not rejecting early

    auto received = pumpUntilReceived(accepted);
    ASSERT_EQ(received.size(), accepted);
    for (uint32_t i = 0; i < accepted; ++i) EXPECT_EQ(received[i], numberedPayload(i, 8 * 1024)) << "frame " << i;

    // Back-pressure is transient: once drained, the queue takes frames again
    const auto next = numberedPayload(accepted, 8 * 1024);
    ASSERT_GT(client->send(&next), 0);
    received = pumpUntilReceived(1);
    ASSERT_EQ(received.size(), 1u);
    EXPECT_EQ(received[0], next);
}

// A message that could never fit the queue is refused up front, even when the socket has room — otherwise one frame
// could pin more memory than the limit allows. The stream stays usable.
TEST_F(SmallSendQueuePair, MessageLargerThanQueueLimitIsRejectedBeforeAnythingIsWritten) {
    const std::vector<uint8_t> tooLarge(QUEUE_LIMIT, 0x77);
    EXPECT_EQ(client->send(&tooLarge), static_cast<ssize_t>(Error::Connection::MessageTooLarge));
    EXPECT_FALSE(client->hasQueuedFrames());

    const auto small = numberedPayload(1, 64);
    ASSERT_GT(client->send(&small), 0);
    const auto received = pumpUntilReceived(1);
    ASSERT_EQ(received.size(), 1u);
    EXPECT_EQ(received[0], small);                                                            // first thing on the wire is the small frame
}

// Unsent frames are useless once the connection is closed — close() must release them at once, and the connection
// must refuse further sends instead of queueing into a dead socket.
TEST_F(EstablishedConnectionPair, CloseReleasesQueuedFramesAndRefusesFurtherSends) {
    sendUntilQueued(16 * 1024);
    ASSERT_TRUE(client->hasQueuedFrames());

    client->close();

    EXPECT_FALSE(client->hasQueuedFrames());
    EXPECT_EQ(client->getQueuedSendBytes(), 0u);
    const std::vector<uint8_t> payload(10, 0x01);
    EXPECT_EQ(client->send(&payload), static_cast<ssize_t>(Error::Connection::SocketClosed));
    EXPECT_EQ(client->writeQueuedFrames(), static_cast<ssize_t>(Error::Connection::SocketClosed));
}

// Stall = frames are queued and none of their bytes moved for a while. An empty queue reports nothing (an idle
// connection is fine, and the owner must not poll POLLOUT for it), and progress restarts the clock.
// Margins are wide (200 ms) so a loaded machine cannot flip the result.
TEST_F(EstablishedConnectionPair, ReportsSendIdleTimeOnlyWhileQueuedFramesMakeNoProgress) {
    EXPECT_FALSE(client->timeSinceSendProgress().has_value());

    sendUntilQueued(16 * 1024);
    ASSERT_TRUE(client->hasQueuedFrames());
    std::this_thread::sleep_for(300ms);
    ASSERT_TRUE(client->timeSinceSendProgress().has_value());
    EXPECT_GT(*client->timeSinceSendProgress(), 200ms);

    // Read part of the backlog and wait until the socket takes more: the queue still holds frames, but it moved
    readRawFromServerSocket(8192);
    pollfd pfd{ clientFd, POLLOUT, 0 };
    ASSERT_EQ(::poll(&pfd, 1, 2000), 1);
    ASSERT_GT(client->writeQueuedFrames(), 0);
    ASSERT_TRUE(client->hasQueuedFrames());
    EXPECT_LT(*client->timeSinceSendProgress(), 200ms);
}

// A failed socket write may leave part of a frame on the wire; from then on nothing may be written, and the error must
// say "stream unusable" (SocketError), not a transient condition — the owner closes on it.
TEST_F(EstablishedConnectionPair, WriteFailureMakesEveryFurtherSendFail) {
    const linger abortive{ 1, 0 };
    ASSERT_EQ(::setsockopt(serverFd, SOL_SOCKET, SO_LINGER, &abortive, sizeof(abortive)), 0);
    server.reset();                                                                           // close with RST

    const std::vector<uint8_t> payload(100, 0x09);
    ssize_t result = 0;
    for (int attempt = 0; attempt < 100 && result >= 0; ++attempt) {                          // the first sends may land before the RST is processed
        result = client->send(&payload);
        if (result >= 0) std::this_thread::sleep_for(10ms);
    }

    ASSERT_EQ(result, static_cast<ssize_t>(Error::Connection::SocketError));
    EXPECT_EQ(client->send(&payload), static_cast<ssize_t>(Error::Connection::SocketError));
    EXPECT_NE(client->getSocket(), -1);                                                       // reporting only — closing stays with the owner
}

// Handshake workers drive the socket themselves before the I/O thread owns the connection: drainSendQueue must block
// until the remote has taken everything...
TEST_F(EstablishedConnectionPair, DrainSendQueueReturnsOnceRemoteTookEverything) {
    const uint32_t sent = sendUntilQueued(16 * 1024);
    ASSERT_TRUE(client->hasQueuedFrames());

    std::vector<std::vector<uint8_t>> received;
    std::thread reader([&] {
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (received.size() < sent && std::chrono::steady_clock::now() < deadline) {
            std::vector<uint8_t> message;
            if (server->receive(message, 10ms) > 0) received.push_back(std::move(message));
        }
    });

    EXPECT_TRUE(client->drainSendQueue(5s));
    EXPECT_FALSE(client->hasQueuedFrames());
    reader.join();
    ASSERT_EQ(received.size(), sent);
    for (uint32_t i = 0; i < sent; ++i) EXPECT_EQ(received[i], numberedPayload(i, 16 * 1024)) << "frame " << i;
}

// ...and give up no earlier than its timeout when the remote does not read. Unsent frames stay queued (the kernel may
// still have taken a little in the meantime), so the stream remains intact for a later flush.
TEST_F(EstablishedConnectionPair, DrainSendQueueTimesOutWhenRemoteDoesNotRead) {
    sendUntilQueued(16 * 1024);
    ASSERT_TRUE(client->hasQueuedFrames());

    const auto start = std::chrono::steady_clock::now();
    EXPECT_FALSE(client->drainSendQueue(50ms));
    EXPECT_GE(std::chrono::steady_clock::now() - start, 50ms);
    EXPECT_TRUE(client->hasQueuedFrames());
}

// Senders on several threads race with the thread flushing the queue (as the management thread races with I/O).
// Frames must never interleave on the wire: every frame decrypts, and each sender's frames keep their order.
TEST_F(EstablishedConnectionPair, ConcurrentSendersNeverInterleaveFrames) {
    constexpr uint32_t SENDERS = 4;
    constexpr uint32_t FRAMES_PER_SENDER = 150;
    std::atomic<bool> sendersDone{false};
    const auto deadline = std::chrono::steady_clock::now() + 10s;                            // every loop is bounded — a broken queue fails, never hangs

    std::vector<std::thread> senders;
    for (uint32_t s = 0; s < SENDERS; ++s) {
        senders.emplace_back([&, s] {
            for (uint32_t i = 0; i < FRAMES_PER_SENDER; ++i) {
                const auto payload = numberedPayload(s * 1000 + i, 1000 + (i * 977) % 20000);   // mixed sizes → partial writes at varying offsets
                while (client->send(&payload) == static_cast<ssize_t>(Error::Connection::SendQueueFull) && std::chrono::steady_clock::now() < deadline) std::this_thread::yield();
            }
        });
    }

    std::thread flusher([&] {
        while ((!sendersDone.load() || client->hasQueuedFrames()) && std::chrono::steady_clock::now() < deadline) {
            client->writeQueuedFrames();
            std::this_thread::yield();
        }
    });

    std::vector<std::vector<uint8_t>> received;
    ssize_t receiveError = 0;
    while (received.size() < SENDERS * FRAMES_PER_SENDER && receiveError == 0 && std::chrono::steady_clock::now() < deadline) {
        std::vector<uint8_t> message;
        const ssize_t n = server->receive(message, 10ms);
        if (n < 0) receiveError = n;
        if (n > 0) received.push_back(std::move(message));
    }

    for (auto& sender : senders) sender.join();
    sendersDone.store(true);
    flusher.join();                                                                           // join before any ASSERT — threads must not outlive the fixture

    ASSERT_EQ(receiveError, 0) << "frames interleaved on the wire";

    ASSERT_EQ(received.size(), SENDERS * FRAMES_PER_SENDER);
    std::array<uint32_t, SENDERS> nextExpected{};
    for (const auto& message : received) {
        uint32_t sequence = 0;
        std::memcpy(&sequence, message.data(), 4);
        const uint32_t sender = sequence / 1000;
        const uint32_t index  = sequence % 1000;
        ASSERT_LT(sender, SENDERS);
        EXPECT_EQ(index, nextExpected[sender]) << "sender " << sender << " frames reordered";
        EXPECT_EQ(message, numberedPayload(sequence, 1000 + (index * 977) % 20000));
        nextExpected[sender] = index + 1;
    }
}

// A backlog of many small frames is flushed in batches of at most 64 per syscall; the front frame's partial offset must
// survive across batches and short writes.
TEST_F(EstablishedConnectionPair, FlushesBacklogLongerThanOneWriteBatch) {
    const uint32_t head = sendUntilQueued(16 * 1024);
    ASSERT_TRUE(client->hasQueuedFrames());
    for (uint32_t i = 0; i < 300; ++i) {
        const auto payload = numberedPayload(head + i, 37 + i % 50);
        ASSERT_GT(client->send(&payload), 0);
    }

    const auto received = pumpUntilReceived(head + 300);
    ASSERT_EQ(received.size(), head + 300);
    for (uint32_t i = 0; i < 300; ++i) EXPECT_EQ(received[head + i], numberedPayload(head + i, 37 + i % 50)) << "frame " << head + i;
    EXPECT_EQ(client->getQueuedSendBytes(), 0u);
}

// close() on the I/O thread races with senders on other threads. Every send must either be accepted before the close
// or refused with SocketClosed afterwards — never touch a closed (possibly recycled) descriptor. Meaningful mainly
// under ThreadSanitizer, which flags any unsynchronized access.
TEST_F(EstablishedConnectionPair, CloseRacingWithSendersIsSafe) {
    std::atomic<bool> stop{false};
    std::atomic<int>  unexpected{0};
    std::vector<std::thread> senders;
    for (int t = 0; t < 3; ++t) {
        senders.emplace_back([&] {
            const std::vector<uint8_t> payload(3000, 0x3C);
            while (!stop.load()) {
                const ssize_t r = client->send(&payload);
                if (r <= 0 && r != static_cast<ssize_t>(Error::Connection::SocketClosed) && r != static_cast<ssize_t>(Error::Connection::SendQueueFull)) ++unexpected;
                client->writeQueuedFrames();
            }
        });
    }

    std::this_thread::sleep_for(20ms);
    client->close();
    std::this_thread::sleep_for(20ms);
    stop.store(true);
    for (auto& sender : senders) sender.join();

    EXPECT_EQ(unexpected.load(), 0);
    EXPECT_EQ(client->getQueuedSendBytes(), 0u);
    const std::vector<uint8_t> payload(10, 0x01);
    EXPECT_EQ(client->send(&payload), static_cast<ssize_t>(Error::Connection::SocketClosed));
}

// ===== Peer on top of the send queue =====

// The peer owns its lifecycle: a send failure that leaves the stream unusable marks it for close, so the I/O thread
// reaps it — no caller has to interpret the error code. Sends to a peer that is not Active never reach the connection.
TEST_F(EstablishedConnectionPair, PeerMarksItselfForCloseWhenItsStreamBreaks) {
    Peer peer(client, PeerIdentity{}, true);
    const std::vector<uint8_t> payload(100, 0x05);
    EXPECT_EQ(peer.send(payload), static_cast<ssize_t>(Error::Connection::SocketClosed));     // Joining — refused
    peer.markActive();

    const linger abortive{ 1, 0 };
    ASSERT_EQ(::setsockopt(serverFd, SOL_SOCKET, SO_LINGER, &abortive, sizeof(abortive)), 0);
    server.reset();

    ssize_t result = 0;
    for (int attempt = 0; attempt < 100 && result >= 0; ++attempt) {
        result = peer.send(payload);
        if (result >= 0) std::this_thread::sleep_for(10ms);
    }

    EXPECT_EQ(result, static_cast<ssize_t>(Error::Connection::SocketError));
    EXPECT_EQ(peer.getState(), PeerState::Closing);
}
