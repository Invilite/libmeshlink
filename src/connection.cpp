#include "meshlink/connection.h"
#include "meshlink/errors.h"
#include "transport/platform.h"

#include <botan/hex.h>
#include <botan/mac.h>
#include <botan/kdf.h>
#include <botan/hash.h>
#include <botan/x448.h>
#include <botan/aead.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/pk_keys.h>
#include <botan/auto_rng.h>
#include <botan/system_rng.h>
#include <botan/stream_cipher.h>

#include <poll.h>
#include <climits>
#include <memory>
#include <iomanip>
#include <iostream>

// Never raise SIGPIPE when the remote is gone — sends run on any thread, including application threads whose signal mask
// we do not control. Linux/BSD suppress it per call (MSG_NOSIGNAL); macOS has no such flag and uses SO_NOSIGPIPE per socket.
#ifdef MSG_NOSIGNAL
constexpr int SEND_FLAGS = MSG_NOSIGNAL;
#else
constexpr int SEND_FLAGS = 0;
#endif

// Upper bound of frames gathered into one sendmsg() call while flushing the send queue.
#ifdef IOV_MAX
constexpr size_t MAX_FRAMES_PER_WRITE = IOV_MAX < 64 ? IOV_MAX : 64;
#else
constexpr size_t MAX_FRAMES_PER_WRITE = 16;
#endif

static const uint16_t crc16Table[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7, 0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6, 0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485, 0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4, 0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
    0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823, 0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
    0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12, 0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41, 0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70, 0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F, 0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E, 0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D, 0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C, 0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB, 0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A, 0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
    0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9, 0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
    0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8, 0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
};

// Only for debugging during development
// static void PrintBuffer(const char* buffer, int length, int headerLen, int pubKeyLen, int signatureLen) {
//     printf("\u001b[0m0x00: ");
//     for (int i = 0; i < length; i++) {
//         if (i < headerLen) {
//             printf("\u001b[38;5;212m");
//         } else if (i < headerLen + pubKeyLen) {
//             printf("\u001b[38;5;118m");
//         } else if (i < headerLen + pubKeyLen + signatureLen) {
//             printf("\u001b[38;5;80m");
//         } else {
//             printf("\u001b[0m");
//         }
//
//         // Print every byte as hexadecimal value
//         printf("0x%02x ", (unsigned char)buffer[i]);
//
//         // New line every 8 bytes
//         if ((i + 1) % 8 == 0) {
//             printf("\n\u001b[0m0x%02x: ", (i)+1);
//             //printf("\n");
//         }
//     }
//     printf("\u001b[0m\n");
// }

// Only for debugging during development
template<typename Container> static void printHex(const Container& data) {
    size_t i = 0;
    for (const uint8_t byte : data) {
        if (i % 16 == 0 && i != 0) std::cout << "\n";
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << ' ';
        ++i;
    }
    std::cout << std::dec << std::endl;
}

invilite::Mesh::Connection::Connection(const int clientSocket, const sockaddr_storage* clientAddress, const std::array<uint8_t, 64>* networkSecret, const size_t sendQueueLimit): clientAddress(*clientAddress), clientSocket(clientSocket), sendQueueLimit(sendQueueLimit), networkSecret(networkSecret) {
    // Verify if socket has correct descriptor
    if (clientSocket < 0) {
        throw std::invalid_argument("Invalid socket descriptor (negative value).");
    }

    // Verify socket type (only TCP stream is allowed)
    int sockType = 0;
    socklen_t optLen = sizeof(sockType);
    if (getsockopt(clientSocket, SOL_SOCKET, SO_TYPE, &sockType, &optLen) == -1 || sockType != SOCK_STREAM) {
        throw std::invalid_argument("Socket is not a TCP stream.");
    }

    // Verify connected socket type
    if (clientAddress->ss_family != AF_INET && clientAddress->ss_family != AF_INET6) {
	    throw std::runtime_error("Unsupported socket type, only tcp IPv4/IPv6 socket is supported.");
	}

    // Verify network secret
    if (networkSecret->empty()) {
        throw std::invalid_argument("Network secret is null or empty");
    }

    // Switch socket to non-blocking mode
    if (!Transport::Platform::setNonBlocking(clientSocket)) {
        throw std::runtime_error("Unable to switch socket to non-blocking mode");
    }

    // Latency only, never correctness — a socket that refuses it still works
    Transport::Platform::disableNagle(clientSocket);

#if !defined(MSG_NOSIGNAL) && defined(SO_NOSIGPIPE)
    const int noSigPipe = 1;
    setsockopt(clientSocket, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, sizeof(noSigPipe));                        // See SEND_FLAGS
#endif

    // Reserve memory for receive buffer initial size
    this->frameBuffer.reserve(bufferMinSize);
}

int invilite::Mesh::Connection::getSocket() const {
    return this->clientSocket;
}

int invilite::Mesh::Connection::initHandshake() {
    // Prepare handshake header
    const std::array<uint8_t, 16> nonce = generateNonce<16>();                                                          // Generate 16 bytes random nonce
    const std::array<uint8_t, 8>  headerMask = calculateHeaderMask(nonce, this->networkSecret);                         // Generate 8 bytes header mask

    std::array<uint8_t, 24> header{};                                                                                   // Reserve 24 bytes for header
    std::copy_n(nonce.begin(), nonce.size(), header.begin());                                                           // Copy nonce as a first 16 bytes
    header[16] = 0x01;                                                                                                  // Handshake protocol version
    header[17] = 0x01;                                                                                                  // Authenticated encryption algorithm
    header[18] = 0x00;                                                                                                  // Reserved
    header[19] = 0x00;                                                                                                  // Reserved
    header[20] = 0x00;                                                                                                  // Reserved
    header[21] = 0x00;                                                                                                  // Reserved

    const uint16_t crc = calculateCRC16(header, 0, header.size() - 2);                                                  // Calculate CRC checksum for header
    header[22] = crc >> 8;                                                                                              // Add CRC checksum to the header
    header[23] = crc & 0xFF;

    // Mask the last 8 bytes of the header (options and CRC)
    for (size_t i = 0; i < 8; i++) {
        header[16 + i] ^= headerMask[i];
    }

    // Generate Elliptic-curve Diffie–Hellman key pair using X448 curve
    Botan::AutoSeeded_RNG rng;
    this->privateKey = std::make_shared<Botan::X448_PrivateKey>(rng);
    const std::vector<uint8_t> pubKeyA = static_cast<Botan::X448_PrivateKey*>(this->privateKey.get())->public_value();

    // Prepare message signature
    const std::unique_ptr<Botan::MessageAuthenticationCode> hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-3(256))");

    // Prepare message to send to remove server
    std::vector<uint8_t> message(header.size() + pubKeyA.size() + hmac->output_length());
    std::ranges::copy(header, message.begin());                                                                         // Copy 24 bytes of header to final message
    std::ranges::copy(pubKeyA, message.begin() + header.size());                                                        // Copy 56 bytes of public key to final message

    // Calculate HMAC<SHA3-256> signature
    hmac->set_key(this->networkSecret->data(), this->networkSecret->size());
    hmac->update(message.data(), header.size() + pubKeyA.size());                                                       // Calculate signature from header and pubKeyA
    hmac->final(message.data() + header.size() + pubKeyA.size());                                                       // Copy HMAC signature to final message

    // Add random size padding with random value
    if constexpr (handshakeMaxPadding > 0) {
        const uint16_t paddingLength = rng.next_byte() % (handshakeMaxPadding + 1);
        std::vector<uint8_t> padding(paddingLength);
        rng.randomize(padding.data(), paddingLength);
        message.insert(message.end(), padding.begin(), padding.end());
    }

    // Send message to remote server
    return this->sendRaw(&message) != static_cast<ssize_t>(message.size());
}

int invilite::Mesh::Connection::waitForHandshake(const milliseconds timeout) {
    constexpr uint32_t expectedLength = 24 + 56 + 32;                                                                   // Header + pubKeyA + HMAC
    constexpr uint32_t maxLength = expectedLength + handshakeMaxPadding;                                                // Message + max. random padding
    std::vector<uint8_t> message;
    message.reserve(maxLength);

    // Wait for full handshake receiving. `timeout` bounds the whole wait, not each chunk — otherwise a client sending one
    // byte just before every timeout keeps the handshake (and its worker thread) alive forever (R1, slowloris).
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    bool handshakeReceived = false;
    while (!handshakeReceived) {
        const auto remaining = std::chrono::ceil<milliseconds>(deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0) {
            return static_cast<int32_t>(Error::Connection::SocketTimeout);
        }
        const ssize_t received = this->receiveRaw<maxLength>(message, remaining, maxLength - static_cast<uint32_t>(message.size()));

        if (received < 0) {
            return static_cast<int32_t>(received);
        }

        if (received == 0) {
            return static_cast<int32_t>(Error::Connection::SocketTimeout);
        }

        if (message.size() >= expectedLength) {
            handshakeReceived = true;
        }
    }

    // This function is called both by the server and client after sending an initial handshake request.
    // If connection doesn't have a private key yet, this is a server side, otherwise it's response from the server to client.
    if (this->privateKey == nullptr) {
        return this->validateHandshake(&message);
    }

    return this->finishHandshake(&message);
}

int invilite::Mesh::Connection::validateHandshake(const std::vector<uint8_t>* message) {
    constexpr size_t expectedLength = 24 + 56 + 32;                                                                     // Header + pubKey + HMAC
    constexpr uint32_t maxLength = expectedLength + handshakeMaxPadding;                                                // Message + max. random padding

    if (message->size() < expectedLength) {
        return static_cast<int32_t>(Error::Connection::LengthMismatch);
    }

    if (message->size() > maxLength) {
        return static_cast<int32_t>(Error::Connection::ReceivedTooMuch);
    }

    std::array<uint8_t, 24> header{};
    std::copy_n(message->begin(), header.size(), header.begin());                                                       // Unpack 24 bytes of header from received message

    std::array<uint8_t, 16> nonce{};                                                        
    std::copy_n(header.begin(), 16, nonce.begin());                                                                     // Unpack 16 bytes nonce from header

    const std::array<uint8_t, 8> headerMask = calculateHeaderMask(nonce, this->networkSecret);                          // Generate 8 bytes header mask
    for (size_t i = 16; i <= 23; ++i) {                                                                                 // Unmask the last 8 bytes of the header (options and CRC)
        header[i] ^= headerMask[i - 16];
    }

    // Calculate CRC for received header
    const uint16_t crc = calculateCRC16(header, 0, header.size() - 2);

    // Check CRC checksum from the header
    if (header[22] != (crc >> 8) || header[23] != (crc & 0xFF)) {
        return static_cast<int32_t>(Error::Connection::ChecksumMismatch);
    }

    // Check requested protocol version (only supported handshake version for now is version 1)
    if (header[16] != 1) {
        return static_cast<int32_t>(Error::Connection::UnsupportedProtocol);
    }

    // Calculate HMAC<SHA3-256> signature for received data
    const std::unique_ptr<Botan::MessageAuthenticationCode> hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-3(256))");
    hmac->set_key(this->networkSecret->data(), this->networkSecret->size());
    hmac->update(message->data(), header.size() + 56);                                                                  // Calculate signature from header and pubKeyA
    std::vector<uint8_t> computedHmac(32);
    hmac->final(computedHmac.data());

    if (!std::equal(computedHmac.begin(), computedHmac.end(), message->begin() + header.size() + 56)) {                 // Compare calculated signature with received
        return static_cast<int32_t>(Error::Connection::SignatureInvalid);
    }

    // -- Client handshake request is now consider valid --

    // Load received public key "A"
    const Botan::AlgorithmIdentifier algorithmId("X448", Botan::AlgorithmIdentifier::USE_NULL_PARAM);
    const Botan::X448_PublicKey pubKeyA(algorithmId, std::span<const uint8_t>(message->data() + header.size(), 56));

    // Generate Elliptic-curve Diffie–Hellman key pair using X448 curve
    Botan::AutoSeeded_RNG rng;
    const Botan::X448_PrivateKey privateKeyB(rng);
    const std::vector<uint8_t> pubKeyB = privateKeyB.public_value();

    // Prepare reply nonce and mask
    const std::array<uint8_t, 16> replyNonce = generateNonce<16>();                                                     // Generate 16 bytes random nonce
    const std::array<uint8_t, 8>  replyMask = calculateHeaderMask(replyNonce, this->networkSecret);                     // Generate 8 bytes header mask

    // Calculate shared secret
    const Botan::PK_Key_Agreement keyAgreement(privateKeyB, rng, "Raw");
    const Botan::secure_vector<uint8_t> sharedSecret = keyAgreement.derive_key(56, pubKeyA.raw_public_key_bits()).bits_of();
    this->sessionKey = deriveEncryptionKey(replyNonce, sharedSecret);
    this->keyFrameCrypto();

    // Prepare reply header
    std::array<uint8_t, 24> replyHeader{};                                                                              // Reserve 24 bytes for header
    std::copy_n(replyNonce.begin(), replyNonce.size(), replyHeader.begin());                                            // Copy nonce as a first 16 bytes
    replyHeader[16] = 0x00;                                                                                             // Reserved
    replyHeader[17] = 0x00;                                                                                             // Reserved
    replyHeader[18] = 0x00;                                                                                             // Reserved
    replyHeader[19] = 0x00;                                                                                             // Reserved
    replyHeader[20] = 0x00;                                                                                             // Reserved
    replyHeader[21] = 0x00;                                                                                             // Reserved

    const uint16_t replyCrc = calculateCRC16(replyHeader, 0, replyHeader.size() - 2);                                   // Calculate CRC checksum for header
    replyHeader[22] = replyCrc >> 8;                                                                                    // Add CRC checksum to the header
    replyHeader[23] = replyCrc & 0xFF;

    // Mask the last 8 bytes of the header (options and CRC)
    for (size_t i = 0; i < 8; i++) {
        replyHeader[16 + i] ^= replyMask[i];
    }

    // Prepare message signature
    const std::unique_ptr<Botan::MessageAuthenticationCode> replyHmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-3(256))");

    // Prepare reply payload
    std::vector<uint8_t> reply(replyHeader.size() + pubKeyB.size() + replyHmac->output_length());
    std::ranges::copy(replyHeader, reply.begin());                                                                      // Copy 24 bytes of header to final reply
    std::ranges::copy(pubKeyB, reply.begin() + replyHeader.size());                                                     // Copy 56 bytes of public key "B" to final reply

    // Calculate HMAC<SHA3-256> signature
    replyHmac->set_key(this->networkSecret->data(), this->networkSecret->size());
    replyHmac->update(reply.data(), header.size() + pubKeyB.size());                                                    // Calculate signature from header and pubKeyB
    replyHmac->final(reply.data() + header.size() + pubKeyB.size());                                                    // Copy HMAC signature to final reply

    // Add random size padding with random value
    if constexpr (handshakeMaxPadding > 0) {
        const size_t paddingLength = rng.next_byte() % (handshakeMaxPadding + 1);
        std::vector<uint8_t> padding(paddingLength);
        rng.randomize(padding.data(), paddingLength);
        reply.insert(reply.end(), padding.begin(), padding.end());
    }

    // Send reply to remote client
    return this->sendRaw(&reply);
}

int invilite::Mesh::Connection::finishHandshake(const std::vector<uint8_t>* message) {
    constexpr size_t expectedLength = 24 + 56 + 32;                                                                     // Header + pubKey + HMAC
    constexpr uint32_t maxLength = expectedLength + handshakeMaxPadding;                                                // Message + max. random padding

    if (message->size() < expectedLength) {
        return static_cast<int32_t>(Error::Connection::LengthMismatch);
    }

    if (message->size() > maxLength) {
        return static_cast<int32_t>(Error::Connection::ReceivedTooMuch);
    }

    std::array<uint8_t, 24> header{};
    std::copy_n(message->begin(), header.size(), header.begin());                                                       // Unpack 24 bytes of header from received message

    std::array<uint8_t, 16> nonce{};                                                        
    std::copy_n(header.begin(), 16, nonce.begin());                                                                     // Unpack 16 bytes nonce from header

    const std::array<uint8_t, 8> headerMask = calculateHeaderMask(nonce, this->networkSecret);                          // Generate 8 bytes header mask
    for (size_t i = 16; i <= 23; ++i) {                                                                                 // Unmask the last 8 bytes of the header (options and CRC) header[16..23]
        header[i] ^= headerMask[i - 16];
    }

    // Calculate CRC for received header
    const uint16_t crc = calculateCRC16(header, 0, header.size() - 2);

    // Check CRC checksum from the header
    if (header[22] != (crc >> 8) || header[23] != (crc & 0xFF)) {
        return static_cast<int32_t>(Error::Connection::ChecksumMismatch);
    }

    // Calculate HMAC<SHA3-256> signature for received data
    const std::unique_ptr<Botan::MessageAuthenticationCode> hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-3(256))");
    hmac->set_key(this->networkSecret->data(), this->networkSecret->size());
    hmac->update(message->data(), header.size() + 56);                                                                  // Calculate signature from header and pubKeyB
    std::vector<uint8_t> computedHmac(32);
    hmac->final(computedHmac.data());

    if (!std::equal(computedHmac.begin(), computedHmac.end(), message->begin() + header.size() + 56)) {                 // Compare calculated signature with received
        return static_cast<int32_t>(Error::Connection::SignatureInvalid);
    }

    // -- Server handshake response is now consider valid --

    // Load received public key "B"
    const Botan::AlgorithmIdentifier algorithmId("X448", Botan::AlgorithmIdentifier::USE_NULL_PARAM);
    const Botan::X448_PublicKey pubKeyB(algorithmId, std::span<const uint8_t>(message->data() + header.size(), 56));

    // Calculate shared secret
    Botan::AutoSeeded_RNG rng;
    const Botan::PK_Key_Agreement keyAgreement(*static_cast<Botan::X448_PrivateKey*>(this->privateKey.get()), rng, "Raw");
    const Botan::secure_vector<uint8_t> sharedSecret = keyAgreement.derive_key(56, pubKeyB.raw_public_key_bits()).bits_of();
    this->sessionKey = deriveEncryptionKey(nonce, sharedSecret);
    this->keyFrameCrypto();

    // Clean private key from memory
    this->privateKey.reset();

    return static_cast<int32_t>(Error::Connection::Success);
}

// Receive raw, unencrypted data
template <uint16_t bufferSize> ssize_t invilite::Mesh::Connection::receiveRaw(std::vector<uint8_t>& data, const milliseconds timeout, const uint32_t maxDataLength) {
    if (this->clientSocket == -1) {
        return static_cast<int32_t>(Error::Connection::SocketClosed);
    }

    struct pollfd pfd;
    pfd.fd = this->clientSocket;
    pfd.events = POLLIN;

    // Wait for data
    const int pollResult = Transport::Platform::waitForSockets(&pfd, 1, static_cast<int>(timeout.count()));

    // Poll error occurred
    if (pollResult < 0) {
        return static_cast<int32_t>(Error::Connection::SelectFailed);
    }

    // Timeout occurred
    if (pollResult == 0) {
        return 0;
    }

    // Remember the base offset — data may already contain bytes from a previous call
    const size_t baseOffset = data.size();
    ssize_t totalReceived = 0;

    while (true) {
        // Receive at most bufferSize bytes per chunk regardless of maxDataLength
        const size_t maxChunkSize = std::min<size_t>(static_cast<size_t>(maxDataLength) - totalReceived, bufferSize);

        if (maxChunkSize == 0) {
            break;
        }

        // Expand buffer to fit incoming chunk — no reallocation if capacity was reserved upfront
        const size_t writeOffset = baseOffset + totalReceived;
        data.resize(writeOffset + maxChunkSize);

        const ssize_t receivedBytes = ::recv(this->clientSocket, data.data() + writeOffset, maxChunkSize, 0);

        // New data received
        if (receivedBytes > 0) {
            // Trim to actually received size
            data.resize(writeOffset + receivedBytes);

            totalReceived += receivedBytes;
            this->bytesReceivedRaw += receivedBytes;

            // Check limits for maxDataLength
            if (totalReceived >= maxDataLength) {
                break;
            }
        } else {
            // Roll back the buffer expansion
            data.resize(writeOffset);

            // Remote peer closed connection
            if (receivedBytes == 0) {
                // EOF — remote closed connection. If we already read some data this call,
                // return it now; the next call will see SocketClosed with zero bytes.
                if (totalReceived > 0) break;
                return static_cast<int32_t>(Error::Connection::SocketClosed);
            }

            // No more data in non-blocking mode
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }

            // If this is interrupt signal, try again
            if (errno != EINTR) {
                // In other case error occurred
                return static_cast<int32_t>(Error::Connection::SocketError);
            }
        }
    }

    return totalReceived;
}

// Send raw, unencrypted data, but wait if socket buffer is full
ssize_t invilite::Mesh::Connection::sendRaw(const std::vector<uint8_t>* data, const size_t offset, const milliseconds timeout) {
    if (this->clientSocket == -1) {
        return static_cast<int32_t>(Error::Connection::SocketClosed);                                                   // Socket is closed
    }

    size_t totalSent = offset;
    while (totalSent < data->size()) {
        struct pollfd pfd;
        pfd.fd     = this->clientSocket;
        pfd.events = POLLOUT;

        // Wait until the socket is ready for writing
        const int pollResult = Transport::Platform::waitForSockets(&pfd, 1, static_cast<int>(timeout.count()));

        if (pollResult < 0) {
            return static_cast<int32_t>(Error::Connection::SelectFailed);                                               // Error occurred in poll
        }

        if (pollResult == 0) {
            return static_cast<int32_t>(Error::Connection::SocketTimeout);                                              // Timeout occurred, socket is not ready for sending
        }

        // Socket is ready for writing
        const ssize_t n = ::send(this->clientSocket, data->data() + totalSent, data->size() - totalSent, SEND_FLAGS);
        if (n > 0) {
            totalSent += n;
            this->bytesSentRaw += n;
        } else if (n == 0) {
            return static_cast<int32_t>(Error::Connection::SocketClosed);                                               // Connection has been closed
        } else {
            // Check if socket is temporarily unavailable, retry if this is a case
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                // Other error, abort sending
                return static_cast<int32_t>(Error::Connection::SocketError);
            }
        }
    }

    return static_cast<ssize_t>(totalSent - offset);
}

ssize_t invilite::Mesh::Connection::receive(std::vector<uint8_t>& data, const milliseconds timeout) {
    // sessionKey should exist after a valid handshake
    if (sessionKey.empty()) {
        return static_cast<int32_t>(Error::Connection::MissingEncryptionKey);
    }

    // Try to process whatever is already in the buffer before touching the socket
    const ssize_t buffered = this->processFrame(data);
    if (buffered != 0) {                                                                                                // Either a complete frame (> 0) or an error (< 0)
        return buffered;
    }

    // Need more data — read from socket. Only the start of one incomplete frame is left in the buffer now; moving it to
    // the front here, once per socket read, keeps consuming frames free of copies (moving the rest after every frame
    // was quadratic in the buffered amount).
    this->compactFrameBuffer();
    if (this->frameBuffer.size() >= messageHardLimit) {                                                                 // Buffer full and still no valid frame — stream is unrecoverable
        return static_cast<int32_t>(Error::Connection::ReceivedTooMuch);
    }

    // Read what the current frame still needs, plus a bounded read-ahead for the frames behind it (one syscall serves
    // many small frames without pulling megabytes into the buffer)
    const size_t missing = (this->frameLength > this->frameBuffer.size()) ? this->frameLength - this->frameBuffer.size() : 0;
    const auto   toRead  = static_cast<uint32_t>(std::max<size_t>(missing, receiveReadAhead));

    const ssize_t receivedLength = this->receiveRaw<16384>(this->frameBuffer, timeout, toRead);

    if (receivedLength < 0) {                                                                                           // Error occurred during data reception
        return receivedLength;
    }

    if (receivedLength == 0) {                                                                                          // Timeout occurred, no data received
        return 0;
    }

    // Try to process the newly received data
    return this->processFrame(data);
}

bool invilite::Mesh::Connection::hasBufferedFrameData() const {
    constexpr size_t packetMinSize = 24 + 8 + 16;                                                                       // nonce + header + tag
    const size_t available = this->frameBuffer.size() - this->frameBufferOffset;
    if (available < packetMinSize) return false;
    return this->frameLength == 0 || available >= this->frameLength;                                                    // header not parsed yet, or the whole frame is here
}

// Returns: > 0 complete frame decrypted, 0 incomplete, < 0 error
ssize_t invilite::Mesh::Connection::processFrame(std::vector<uint8_t>& data) {
    constexpr size_t nonceSize    = 24;
    constexpr size_t headerSize   = 8;
    constexpr size_t tagSize      = 16;
    constexpr size_t packetMinSize = nonceSize + headerSize + tagSize;

    // Not enough data to even attempt processing
    const size_t available = this->frameBuffer.size() - this->frameBufferOffset;
    if (available < packetMinSize) {
        return 0;
    }

    // Parse header if we haven't yet
    if (this->frameLength == 0) {
        const std::span<const uint8_t> pending(this->frameBuffer.data() + this->frameBufferOffset, available);
        if (!isValidFrameHeader(pending, this->frameLength, this->frameFlags)) {
            return static_cast<int32_t>(Error::Connection::InvalidFrameHeader);
        }

        if (this->frameLength > messageHardLimit) {                                                                     // Reject frames exceeding hard limit — we can't recover stream sync
            return static_cast<int32_t>(Error::Connection::ReceivedTooMuch);
        }

        if (this->frameLength > available && this->frameBufferOffset + this->frameLength > this->frameBuffer.capacity()) {
            this->compactFrameBuffer();                                                                                 // Large frame: start it at the front, then reserve its exact size —
            this->frameBuffer.reserve(this->frameLength);                                                               // receiveRaw will write directly without reallocation
        }
    }

    // Frame is not complete yet
    if (this->frameBuffer.size() - this->frameBufferOffset < this->frameLength) {
        return 0;
    }

    // We have a complete frame — decrypt it
    try {
        const std::span<const uint8_t> frame(this->frameBuffer.data() + this->frameBufferOffset, this->frameLength);
        std::vector<uint8_t> decryptedData = this->decryptData(frame);

        // TODO: Implement compression in the future
        // if (this->frameFlags) { }

        const ssize_t finalDataSize = static_cast<ssize_t>(decryptedData.size());
        data = std::move(decryptedData);                                                                                // Move decrypted data to output buffer — no copy

        // Consume the frame by advancing the offset; once everything is consumed, start over at the front for free
        this->frameBufferOffset += this->frameLength;
        if (this->frameBufferOffset == this->frameBuffer.size()) {
            this->frameBuffer.clear();
            this->frameBufferOffset = 0;
            if (this->frameBuffer.capacity() > bufferSoftLimit) {                                                       // Give back memory after a large frame
                std::vector<uint8_t>().swap(this->frameBuffer);
                this->frameBuffer.reserve(bufferMinSize);
            }
        }

        this->frameLength = 0;
        this->frameFlags  = 0;
        this->bytesReceived += finalDataSize;

        return finalDataSize;

    } catch (const std::exception&) {
        return static_cast<int32_t>(Error::Connection::DecryptionError);
    }
}

void invilite::Mesh::Connection::compactFrameBuffer() {
    if (this->frameBufferOffset == 0) return;
    const size_t remaining = this->frameBuffer.size() - this->frameBufferOffset;
    if (remaining > 0) std::memmove(this->frameBuffer.data(), this->frameBuffer.data() + this->frameBufferOffset, remaining);
    this->frameBuffer.resize(remaining);
    this->frameBufferOffset = 0;
}

ssize_t invilite::Mesh::Connection::send(const std::vector<uint8_t>* data) {
    if (sessionKey.empty()) {                                                                                           // Set once by the handshake, before the connection is shared
        return static_cast<int32_t>(Error::Connection::MissingEncryptionKey);
    }

    constexpr size_t overhead = 24 + 8 + 16;                                                                            // nonce + header + Poly1305 tag
    if (data->size() > messageHardLimit - overhead || data->size() + overhead > this->sendQueueLimit) {                // Such a frame could never be accepted — reject before encrypting
        return static_cast<int32_t>(Error::Connection::MessageTooLarge);
    }

    const size_t frameSize = data->size() + overhead;
    {
        // Cheap rejection before encrypting — a send toward a peer whose queue is full must not burn CPU and memory on crypto
        std::lock_guard lock(this->sendQueueMutex);
        if (const ssize_t refusal = this->checkFrameFitsLocked(frameSize); refusal < 0) return refusal;
    }

    std::vector<uint8_t> frame = this->encryptData(*data);                                                              // Encrypt outside the lock — senders on other threads keep going

    std::lock_guard lock(this->sendQueueMutex);
    if (const ssize_t refusal = this->checkFrameFitsLocked(frame.size()); refusal < 0) return refusal;                 // Re-check: the queue may have changed while encrypting

    const bool queueWasEmpty = this->sendQueue.empty();
    this->queuedFrameBytes += frame.size();
    this->sendQueue.push_back(std::move(frame));

    // Fast path: nothing was waiting, so write now. Behind queued frames we must not write — the I/O thread flushes in order.
    if (queueWasEmpty) {
        const ssize_t written = this->writeQueuedFramesLocked();
        if (written < 0) return written;
        if (!this->sendQueue.empty()) this->lastSendProgressAt = std::chrono::steady_clock::now();                      // Start the stall clock for the remainder
    }

    this->bytesSent += data->size();
    return static_cast<ssize_t>(data->size());
}

ssize_t invilite::Mesh::Connection::checkFrameFitsLocked(const size_t frameSize) const {
    if (this->clientSocket == -1 || this->sendFinishing) return static_cast<int32_t>(Error::Connection::SocketClosed);
    if (this->sendStreamFailed)   return static_cast<int32_t>(Error::Connection::SocketError);
    if (this->queuedFrameBytes + frameSize > this->sendQueueLimit) {                                                    // Only reachable with frames already queued — an empty queue takes any frame up to the limit
        return static_cast<int32_t>(Error::Connection::SendQueueFull);
    }
    return 0;
}

ssize_t invilite::Mesh::Connection::writeQueuedFrames() {
    std::lock_guard lock(this->sendQueueMutex);
    if (this->clientSocket == -1) return static_cast<int32_t>(Error::Connection::SocketClosed);
    if (this->sendStreamFailed)   return static_cast<int32_t>(Error::Connection::SocketError);

    const ssize_t written = this->writeQueuedFramesLocked();
    if (written > 0 && !this->sendQueue.empty()) this->lastSendProgressAt = std::chrono::steady_clock::now();
    return written;
}

ssize_t invilite::Mesh::Connection::writeQueuedFramesLocked() {
    size_t totalWritten = 0;

    while (!this->sendQueue.empty()) {
        // Gather several queued frames into one syscall — a backlog of small frames costs one write, not one per frame
        std::array<iovec, MAX_FRAMES_PER_WRITE> iov{};
        size_t iovCount  = 0;
        size_t requested = 0;
        for (auto it = this->sendQueue.begin(); it != this->sendQueue.end() && iovCount < iov.size(); ++it, ++iovCount) {
            const size_t skip = (iovCount == 0) ? this->sendQueueFrontOffset : 0;                                      // The front frame may be partly written already
            iov[iovCount].iov_base = it->data() + skip;
            iov[iovCount].iov_len  = it->size() - skip;
            requested += iov[iovCount].iov_len;
        }

        msghdr message{};
        message.msg_iov    = iov.data();
        message.msg_iovlen = iovCount;

        const ssize_t n = ::sendmsg(this->clientSocket, &message, SEND_FLAGS);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;                                                         // Socket full — the rest waits for the next POLLOUT
            this->sendStreamFailed = true;                                                                              // Part of a frame may be on the wire — never write again
            return static_cast<int32_t>(Error::Connection::SocketError);
        }

        totalWritten += static_cast<size_t>(n);
        this->bytesSentRaw += static_cast<uint64_t>(n);

        // Drop fully written frames; remember how far into the next one we got
        size_t remaining = static_cast<size_t>(n);
        while (remaining > 0) {
            const size_t frontLeft = this->sendQueue.front().size() - this->sendQueueFrontOffset;
            if (remaining < frontLeft) {
                this->sendQueueFrontOffset += remaining;
                break;
            }
            remaining -= frontLeft;
            this->queuedFrameBytes -= this->sendQueue.front().size();                                                 // Memory is released only now, with the whole frame
            this->sendQueue.pop_front();
            this->sendQueueFrontOffset = 0;
        }

        if (static_cast<size_t>(n) < requested) break;                                                                  // Short write — the kernel buffer is full, skip the EAGAIN round trip
    }

    this->shutDownSendDirectionIfFinishedLocked();
    return static_cast<ssize_t>(totalWritten);
}

void invilite::Mesh::Connection::shutDownSendDirectionIfFinishedLocked() {
    if (!this->sendFinishing || !this->sendQueue.empty() || this->sendDirectionShutDown || this->clientSocket == -1) return;
    ::shutdown(this->clientSocket, SHUT_WR);                                                                            // FIN after the last queued byte
    this->sendDirectionShutDown = true;
}

void invilite::Mesh::Connection::finishSending() {
    std::lock_guard lock(this->sendQueueMutex);
    this->sendFinishing = true;
    this->shutDownSendDirectionIfFinishedLocked();                                                                     // Nothing queued → half-close now; otherwise the last flush does it
}

bool invilite::Mesh::Connection::drainSendQueue(const milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;

    while (true) {
        int socket;
        {
            std::lock_guard lock(this->sendQueueMutex);
            if (this->sendQueue.empty()) return true;
            if (this->clientSocket == -1 || this->sendStreamFailed) return false;
            if (this->writeQueuedFramesLocked() < 0) return false;
            if (this->sendQueue.empty()) return true;
            socket = this->clientSocket;
        }

        const auto left = std::chrono::ceil<milliseconds>(deadline - std::chrono::steady_clock::now());               // Round up — never give up before the deadline
        if (left.count() <= 0) return false;

        pollfd pfd{ socket, POLLOUT, 0 };
        if (Transport::Platform::waitForSockets(&pfd, 1, static_cast<int>(left.count())) < 0 && errno != EINTR) return false;
    }
}

bool invilite::Mesh::Connection::hasQueuedFrames() const {
    std::lock_guard lock(this->sendQueueMutex);
    return !this->sendQueue.empty();
}

size_t invilite::Mesh::Connection::getQueuedSendBytes() const {
    std::lock_guard lock(this->sendQueueMutex);
    return this->queuedFrameBytes;
}

std::optional<std::chrono::steady_clock::duration> invilite::Mesh::Connection::timeSinceSendProgress() const {
    std::lock_guard lock(this->sendQueueMutex);
    if (this->sendQueue.empty()) return std::nullopt;                                                                   // No clock read on the common, idle path
    return std::chrono::steady_clock::now() - this->lastSendProgressAt;
}

void invilite::Mesh::Connection::keyFrameCrypto() {
    this->frameEncryptor = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Encryption);   // 24-byte nonce → XChaCha20
    this->frameEncryptor->set_key(this->sessionKey);
    this->frameDecryptor = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305", Botan::Cipher_Dir::Decryption);
    this->frameDecryptor->set_key(this->sessionKey);
    this->sendHeaderMac = Botan::MessageAuthenticationCode::create_or_throw("BLAKE2b(64)");
    this->sendHeaderMac->set_key(this->sessionKey);
    this->receiveHeaderMac = Botan::MessageAuthenticationCode::create_or_throw("BLAKE2b(64)");
    this->receiveHeaderMac->set_key(this->sessionKey);
}

std::array<uint8_t, 8> invilite::Mesh::Connection::frameHeaderMask(Botan::MessageAuthenticationCode& mac, const std::span<const uint8_t> nonce) const {
    mac.update(nonce.data(), nonce.size());
    const auto digest = mac.final();                                                                                    // final() also resets the MAC for the next frame, keeping the key
    std::array<uint8_t, 8> mask{};
    std::copy_n(digest.begin(), mask.size(), mask.begin());
    return mask;
}

std::vector<uint8_t> invilite::Mesh::Connection::encryptData(const std::vector<uint8_t>& data) {
    constexpr size_t nonceSize  = 24;
    constexpr size_t headerSize = 8;
    constexpr size_t tagSize    = 16;
    const std::array<uint8_t, nonceSize> nonce = generateNonce<nonceSize>();                                            // Random 24-byte nonce (XChaCha20)

    // Frame layout: nonce | masked header | ciphertext | tag — built in one buffer, the payload copied in once and
    // encrypted in place
    const auto frameLen = static_cast<uint32_t>(nonceSize + headerSize + data.size() + tagSize);
    std::vector<uint8_t> frame(frameLen);
    std::ranges::copy(nonce, frame.begin());

    uint8_t* header = frame.data() + nonceSize;
    header[0] = 0x01;                                                                                                   // Protocol version
    header[1] = 0x00;                                                                                                   // Flags (compression?)
    header[2] = (frameLen >> 24) & 0xFF;                                                                                // Packet length (big-endian)
    header[3] = (frameLen >> 16) & 0xFF;
    header[4] = (frameLen >> 8) & 0xFF;
    header[5] =  frameLen & 0xFF;
    const uint16_t crc = calculateCRC16(frame, nonceSize, nonceSize + headerSize - 2);                                 // CRC over the first 6 header bytes
    header[6] = (crc >> 8) & 0xFF;
    header[7] = crc & 0xFF;

    uint8_t* body = frame.data() + nonceSize + headerSize;
    std::copy(data.begin(), data.end(), body);

    std::lock_guard lock(this->encryptMutex);                                                                           // senders on several threads share the keyed objects
    const std::array<uint8_t, 8> headerMask = this->frameHeaderMask(*this->sendHeaderMac, nonce);
    for (size_t i = 0; i < headerSize; i++) {
        header[i] ^= headerMask[i];                                                                                     // Mask the header (DPI resistance)
    }

    this->frameEncryptor->set_associated_data(header, headerSize);                                                     // must precede start(): the masked header is authenticated
    this->frameEncryptor->start(nonce.data(), nonce.size());
    this->frameEncryptor->process(body, data.size());                                                                  // encrypt in place
    Botan::secure_vector<uint8_t> tag;
    this->frameEncryptor->finish(tag);                                                                                  // empty final block → only the Poly1305 tag
    std::copy(tag.begin(), tag.end(), body + data.size());

    return frame;
}

bool invilite::Mesh::Connection::isValidFrameHeader(const std::span<const uint8_t> frame, uint32_t& packetSize, uint8_t& flags) const {
    constexpr size_t nonceSize  = 24;
    constexpr size_t headerSize = 8;

    // Frame must contain at least nonce + header
    if (frame.size() < nonceSize + headerSize) {
        return false;
    }

    std::array<uint8_t, nonceSize> nonce{};
    std::array<uint8_t, headerSize> header{};
    std::copy_n(frame.begin(), nonce.size(), nonce.begin());                                                            // Unpack nonce (initialization vector) from frame
    std::copy_n(frame.begin() + nonce.size(), header.size(), header.begin());                                           // Unpack frame header
    const std::array<uint8_t, 8> headerMask = this->frameHeaderMask(*this->receiveHeaderMac, nonce);                    // keyed once with the session key

    // Unmask the header
    for (size_t i = 0; i < 8; i++) {
        header[i] ^= headerMask[i];
    }

    // Calculate and verify CRC checksum for first 6 bytes of header
    const uint16_t expectedCRC = (static_cast<uint16_t>(header[6]) << 8) | header[7];
    const uint16_t calculatedCRC = calculateCRC16(header, 0, header.size() - 2);

    if (calculatedCRC != expectedCRC) {
        return false;
    }

    if (header[0] != 0x01) {                                                                                            // Check if protocol version is supported
        return false;
    }

    flags = header[1];

    // Get frame size (big-endian)
    packetSize = (static_cast<uint32_t>(header[2]) << 24)
               | (static_cast<uint32_t>(header[3]) << 16)
               | (static_cast<uint32_t>(header[4]) << 8)
               |  static_cast<uint32_t>(header[5]);

    // A frame always carries nonce + header + Poly1305 tag; a smaller declared size would make the
    // ciphertext range in decryptData negative.
    constexpr size_t tagSize = 16;
    if (packetSize < nonceSize + headerSize + tagSize) {
        return false;
    }

    return true;
}

std::vector<uint8_t> invilite::Mesh::Connection::decryptData(const std::span<const uint8_t> frame) {
    const size_t frameSize = frame.size();
    constexpr size_t nonceSize = 24;
    constexpr size_t headerSize = 8;
    constexpr size_t tagSize = 16;
    constexpr size_t packetMinSize = nonceSize + headerSize + tagSize;

    // Check is packet have minimal required size to decrypt
    if (frameSize < packetMinSize) {
        throw std::runtime_error("Packet is incomplete, unable to decrypt.");
    }

    // One copy: the ciphertext into the output, decrypted there in place; the tag is verified separately
    const auto bodyBegin = frame.begin() + nonceSize + headerSize;
    const auto tagBegin  = frame.begin() + static_cast<std::ptrdiff_t>(frameSize - tagSize);
    std::vector<uint8_t> plain(bodyBegin, tagBegin);
    Botan::secure_vector<uint8_t> tag(tagBegin, tagBegin + tagSize);

    try {
        this->frameDecryptor->set_associated_data(frame.data() + nonceSize, headerSize);
        this->frameDecryptor->start(frame.data(), nonceSize);
        this->frameDecryptor->process(plain.data(), plain.size());
        this->frameDecryptor->finish(tag);                                                                              // verifies the tag — throws when the frame was tampered with
        return plain;
    } catch (const Botan::Exception& e) {
        throw std::runtime_error(std::string("Decryption failed: ") + e.what());
    }
}

std::vector<uint8_t> invilite::Mesh::Connection::deriveEncryptionKey(std::array<uint8_t, 16> nonce, const std::span<const uint8_t> secret) {
    const std::string label = "SessionEncryptionKey";
    const std::unique_ptr<Botan::KDF> kdf = Botan::KDF::create_or_throw("HKDF(HMAC(SHA-256))");
    constexpr size_t keyLength = 32;
    const Botan::secure_vector<uint8_t> key = kdf->derive_key(keyLength, secret, std::string(nonce.begin(), nonce.end()), label);

    return std::vector<uint8_t>(key.begin(), key.end());
}

std::string invilite::Mesh::Connection::getRemoteClientAddress() const {
    char remoteClientAddress[INET6_ADDRSTRLEN];

    if (this->clientAddress.ss_family == AF_INET) {
        // Incoming IPv4 connection
        const auto& addr4 = reinterpret_cast<const sockaddr_in&>(this->clientAddress);
        inet_ntop(AF_INET, &addr4.sin_addr, remoteClientAddress, sizeof(remoteClientAddress));
    } else if (this->clientAddress.ss_family == AF_INET6) {
        // Incoming IPv6 connection
        const auto& addr6 = reinterpret_cast<const sockaddr_in6&>(this->clientAddress);
        inet_ntop(AF_INET6, &addr6.sin6_addr, remoteClientAddress, sizeof(remoteClientAddress));
    } else {
        throw std::runtime_error("Unsupported socket type, only tcp IPv4/IPv6 socket is supported.");
    }

    return std::string(remoteClientAddress);
}

uint16_t invilite::Mesh::Connection::getRemoteClientPort() const {
    uint16_t remoteClientPort;
    if (this->clientAddress.ss_family == AF_INET) {
        // Incoming IPv4 connection
        const auto& addr4 = reinterpret_cast<const sockaddr_in&>(this->clientAddress);
        remoteClientPort = ntohs(addr4.sin_port);
    } else if (this->clientAddress.ss_family == AF_INET6) {
        // Incoming IPv6 connection
        const auto& addr6 = reinterpret_cast<const sockaddr_in6&>(this->clientAddress);
        remoteClientPort = ntohs(addr6.sin6_port);
    } else {
        throw std::runtime_error("Unsupported socket type, only tcp IPv4/IPv6 socket is supported.");
    }

    return remoteClientPort;
}

invilite::Mesh::Connection::~Connection() {
    this->close();
}

void invilite::Mesh::Connection::close() {
    std::lock_guard lock(this->sendQueueMutex);                                                                         // No sender may hold the descriptor while it is closed
    if (this->clientSocket != -1) {
        ::shutdown(this->clientSocket, SHUT_WR);
        ::close(this->clientSocket);
        this->clientSocket = -1;
    }

    // Unsent frames can never be delivered now — release their memory right away (swap also frees the deque's blocks)
    std::deque<std::vector<uint8_t>>().swap(this->sendQueue);
    this->sendQueueFrontOffset = 0;
    this->queuedFrameBytes     = 0;
}

uint64_t invilite::Mesh::Connection::getBytesSent() const {
    return this->bytesSent;
}

uint64_t invilite::Mesh::Connection::getBytesReceived() const {
    return this->bytesReceived;
}

uint64_t invilite::Mesh::Connection::getBytesSentRaw() const {
    return this->bytesSentRaw;
}

uint64_t invilite::Mesh::Connection::getBytesReceivedRaw() const {
    return this->bytesReceivedRaw;
}

uint16_t invilite::Mesh::Connection::calculateCRC16(const std::vector<uint8_t>& data) {
    uint16_t crc = 0x16AB;

    for (size_t i = 0; i < data.size(); ++i) {
        const uint8_t index = (crc >> 8) ^ data[i];
        crc = crc16Table[index] ^ (crc << 8);
    }

    return crc;
}

template <typename Container> uint16_t invilite::Mesh::Connection::calculateCRC16(const Container& data, const size_t start, const size_t end) {
    uint16_t crc = 0x16AB;
    
    for (size_t i = start; i < end; ++i) {
        const uint8_t index = (crc >> 8) ^ data[i];
        crc = crc16Table[index] ^ (crc << 8);
    }

    return crc;
}

template<std::uint8_t length>
std::array<uint8_t, length> invilite::Mesh::Connection::generateNonce() {
    // The OS CSPRNG (getrandom): ~40 ns, thread-safe, stateless. AutoSeeded_RNG cost ~6 µs per call even when reused
    // (it mixes extra input and updates its DRBG on every request) and ~5 µs more to construct — per frame.
    std::array<uint8_t, length> nonce{};
    Botan::system_rng().randomize(nonce.data(), nonce.size());

    return nonce;
}

template<std::size_t nonceLength>
std::array<uint8_t, 8> invilite::Mesh::Connection::calculateHeaderMask(const std::array<uint8_t, nonceLength>& nonce, const std::array<uint8_t, 64>* secret) {
    const auto mac = Botan::MessageAuthenticationCode::create_or_throw("BLAKE2b(64)");
    mac->set_key(secret->data(), secret->size());
    mac->update(nonce.data(), nonce.size());
    const auto result = mac->final();

    std::array<uint8_t, 8> mask{};
    std::copy_n(result.begin(), 8, mask.begin());

    return mask;
}

template<std::size_t nonceLength>
std::array<uint8_t, 8> invilite::Mesh::Connection::calculateHeaderMask(const std::array<uint8_t, nonceLength>& nonce, const std::vector<uint8_t>& secret) {
    const auto mac = Botan::MessageAuthenticationCode::create_or_throw("BLAKE2b(64)");
    mac->set_key(secret.data(), secret.size());
    mac->update(nonce.data(), nonce.size());
    const auto result = mac->final();

    std::array<uint8_t, 8> mask{};
    std::copy_n(result.begin(), 8, mask.begin());

    return mask;
}
