#pragma once

#ifndef MESH_CONNECTION_H
#define MESH_CONNECTION_H

#include <span>
#include <array>
#include <chrono>
#include <memory>
#include <vector>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <sys/socket.h>

using std::chrono::milliseconds;

namespace invilite::Mesh {

// Transport layer protocol
class Connection {
public:
	Connection(int clientSocket, const sockaddr_storage* clientAddress, const std::array<uint8_t, 64>* networkSecret);
	int initHandshake();																								// Client initiates a handshake
	int waitForHandshake(milliseconds timeout = milliseconds(3000));													// Server waits for a client to start a handshake
	ssize_t receive(std::vector<uint8_t>& data, milliseconds timeout = milliseconds(100));								// Wait for incoming packet of data and decrypt it
    ssize_t send(const std::vector<uint8_t>* data);																		// Encrypt data and send it
	int getSocket() const;
	void close();

    std::string getRemoteClientAddress() const;
    uint16_t getRemoteClientPort() const;
	uint64_t getBytesSent() const;
	uint64_t getBytesReceived() const;
	uint64_t getBytesSentRaw() const;
	uint64_t getBytesReceivedRaw() const;

protected:
	int validateHandshake(const std::vector<uint8_t>* message);
	int finishHandshake(const std::vector<uint8_t>* message);
	bool isValidFrameHeader(const std::vector<uint8_t> &frame, uint32_t &packetSize, uint8_t &flags) const;
	template <uint16_t bufferSize> ssize_t receiveRaw(std::vector<uint8_t>& data, milliseconds timeout = milliseconds(100), uint32_t maxDataLength = 104857600);
	ssize_t sendRaw(const std::vector<uint8_t>* data, size_t offset = 0, milliseconds timeout = milliseconds(100));
	ssize_t processFrame(std::vector<uint8_t>& data);
	std::vector<uint8_t> encryptData(const std::vector<uint8_t>& data);
	std::vector<uint8_t> decryptData(const std::vector<uint8_t>& frame, size_t frameSize);
	template <std::size_t nonceLength> static std::array<uint8_t, 8> calculateHeaderMask(const std::array<uint8_t, nonceLength>& nonce, const std::array<uint8_t, 64>* secret);
	template <std::size_t nonceLength> static std::array<uint8_t, 8> calculateHeaderMask(const std::array<uint8_t, nonceLength>& nonce, const std::vector<uint8_t>& secret);
	template<std::uint8_t length> static std::array<uint8_t, length> generateNonce();
	template <typename Container> static uint16_t calculateCRC16(const Container& data, size_t start, size_t end);
	static uint16_t calculateCRC16(const std::vector<uint8_t>& data);
	static std::vector<uint8_t> deriveEncryptionKey(std::array<uint8_t, 16> nonce, std::span<const uint8_t> secret);

	const sockaddr_storage clientAddress;
	std::vector<uint8_t> frameBuffer;
    uint32_t frameLength = 0;
    uint8_t  frameFlags = 0;

	uint64_t bytesReceivedRaw = 0;
	uint64_t bytesSentRaw = 0;
	uint64_t bytesReceived = 0;
	uint64_t bytesSent = 0;

private:
	int clientSocket;
	const std::array<uint8_t, 64>* networkSecret;
	std::vector<uint8_t> sessionKey;																					// Session key is negotiated during handshake
	std::shared_ptr<void> privateKey;																					// Only for client-node (that started connection)

	constexpr static uint8_t handshakeMaxPadding = 255;																	// Max padding for handshake request and reply
	constexpr static uint32_t bufferMinSize = 1024;																		// Frame buffer initial size
	constexpr static uint32_t bufferSoftLimit = 3145728;																// Frame buffer will shrink to this size (3MB) after receive large packet over bufferSoftLimit
	constexpr static uint32_t messageHardLimit = 16777216;																// Largest possible frame size (16MB) that can be transferred
};

} // namespace invilite::Mesh

#endif // MESH_CONNECTION_H