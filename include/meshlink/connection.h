#pragma once

#ifndef MESH_CONNECTION_H
#define MESH_CONNECTION_H

#include <span>
#include <array>
#include <atomic>
#include <chrono>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <sys/socket.h>

using std::chrono::milliseconds;

namespace Botan {
	class AEAD_Mode;
	class MessageAuthenticationCode;
}

namespace invilite::Mesh {

// Transport layer protocol
class Connection {
public:
	constexpr static size_t defaultSendQueueLimit = 1048576;															// 1MB — bounds memory held for one slow reader

	// sendQueueLimit caps the bytes of encrypted frames waiting for the socket; it is also the largest frame send() accepts.
	Connection(int clientSocket, const sockaddr_storage* clientAddress, const std::array<uint8_t, 64>* networkSecret, size_t sendQueueLimit = defaultSendQueueLimit);
	~Connection();																										// Closes the socket if still open — Connection owns it
	Connection(const Connection&)            = delete;																	// Unique socket ownership: copying would double-close
	Connection& operator=(const Connection&) = delete;
	int initHandshake();																								// Client initiates a handshake
	int waitForHandshake(milliseconds timeout = milliseconds(3000));													// Server waits for a client to start a handshake
	// receive() never closes the socket. A negative result means the stream is unusable — the owner must close().
	// Closing stays with the owner so it can be serialized with sends running on other threads.
	ssize_t receive(std::vector<uint8_t>& data, milliseconds timeout = milliseconds(100));								// Wait for incoming packet of data and decrypt it
	// True when receive() may complete a frame from bytes already read into the frame buffer — poll() cannot see those,
	// so an owner that stops reading early must call receive() again without waiting for a socket event.
	// Conservative: may be true for an unparsed header that turns out incomplete; false means socket data is needed.
	bool hasBufferedFrameData() const;
	// send() encrypts the message and hands it to the socket without ever blocking. Thread-safe.
	// Nothing queued → the frame is written straight away and only the part the kernel did not take is queued (no extra
	// copy, syscall or wakeup on this path). Frames already queued → the new frame is appended behind them, keeping order.
	// A frame is always written whole and in order, so the stream never carries a torn frame.
	// Returns the plaintext size once the frame is accepted (written or queued), or a negative error:
	//   SendQueueFull / MessageTooLarge / MissingEncryptionKey — frame dropped, stream intact
	//   SocketError / SocketClosed — stream unusable, the owner must close()
    ssize_t send(const std::vector<uint8_t>* data);
	// Writes as much of the send queue as the socket takes now, without blocking. The owner calls it when the socket is
	// writable. Returns bytes written (0 = socket still full), or a negative error — stream unusable, the owner must close().
	ssize_t writeQueuedFrames();
	// Blocks until the send queue is empty (true) or the timeout passes / the stream fails (false). Only for ephemeral
	// threads (handshake workers) that drive the socket themselves before the I/O thread takes the connection over.
	bool drainSendQueue(milliseconds timeout);
	// Graceful half-close: no further frames are accepted, and once everything already queued has been written the
	// write direction is shut down (the remote reads EOF) — while this side keeps reading. Used by the departure window.
	void finishSending();
	bool hasQueuedFrames() const;
	size_t getQueuedSendBytes() const;																					// Memory held by queued frames (see queuedFrameBytes)
	// How long queued frames have been waiting without any byte reaching the socket; nullopt when nothing is queued.
	// One call gives the owner both "poll for POLLOUT?" and "has the remote stopped reading?".
	std::optional<std::chrono::steady_clock::duration> timeSinceSendProgress() const;
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
	bool isValidFrameHeader(std::span<const uint8_t> frame, uint32_t &packetSize, uint8_t &flags) const;
	template <uint16_t bufferSize> ssize_t receiveRaw(std::vector<uint8_t>& data, milliseconds timeout = milliseconds(100), uint32_t maxDataLength = 104857600);
	// Blocking send for handshake messages only — runs on an ephemeral worker before the connection carries frames.
	ssize_t sendRaw(const std::vector<uint8_t>* data, size_t offset = 0, milliseconds timeout = milliseconds(100));
	ssize_t writeQueuedFramesLocked();																					// Caller holds sendQueueMutex
	ssize_t checkFrameFitsLocked(size_t frameSize) const;																// 0 or the refusal send() returns; caller holds sendQueueMutex
	void shutDownSendDirectionIfFinishedLocked();																		// SHUT_WR once finishing and drained; caller holds sendQueueMutex
	ssize_t processFrame(std::vector<uint8_t>& data);
	std::vector<uint8_t> encryptData(const std::vector<uint8_t>& data);
	std::vector<uint8_t> decryptData(std::span<const uint8_t> frame);													// `frame` is exactly one whole frame
	void compactFrameBuffer();																							// Move the unprocessed tail to the front
	template <std::size_t nonceLength> static std::array<uint8_t, 8> calculateHeaderMask(const std::array<uint8_t, nonceLength>& nonce, const std::array<uint8_t, 64>* secret);
	template <std::size_t nonceLength> static std::array<uint8_t, 8> calculateHeaderMask(const std::array<uint8_t, nonceLength>& nonce, const std::vector<uint8_t>& secret);
	template<std::uint8_t length> static std::array<uint8_t, length> generateNonce();
	template <typename Container> static uint16_t calculateCRC16(const Container& data, size_t start, size_t end);
	static uint16_t calculateCRC16(const std::vector<uint8_t>& data);
	static std::vector<uint8_t> deriveEncryptionKey(std::array<uint8_t, 16> nonce, std::span<const uint8_t> secret);

	const sockaddr_storage clientAddress;
	std::vector<uint8_t> frameBuffer;
	size_t frameBufferOffset = 0;																						// Start of unprocessed bytes — frames are consumed by advancing it, not by moving the rest
    uint32_t frameLength = 0;
    uint8_t  frameFlags = 0;

	uint64_t bytesReceivedRaw = 0;
	std::atomic<uint64_t> bytesSentRaw = 0;																				// Atomic — senders run on any thread
	uint64_t bytesReceived = 0;
	std::atomic<uint64_t> bytesSent = 0;

private:
	std::atomic<int> clientSocket;																						// Atomic — read by senders on any thread, reset by close()

	// Send queue — encrypted frames the kernel has not taken yet. sendQueueMutex guards these fields and every write to
	// the socket, and close(), so frames never interleave and nothing is written to a closed (or recycled) descriptor.
	mutable std::mutex sendQueueMutex;
	std::deque<std::vector<uint8_t>> sendQueue;
	size_t sendQueueFrontOffset = 0;																					// Bytes of sendQueue.front() already written
	size_t queuedFrameBytes = 0;																						// Full size of every queued frame — the memory actually held (the written part of the front frame is freed only when it pops), checked against sendQueueLimit
	const size_t sendQueueLimit;
	bool sendStreamFailed = false;																						// A socket write failed — nothing may be written anymore
	bool sendFinishing = false;																							// finishSending() called — accept no new frames
	bool sendDirectionShutDown = false;																					// SHUT_WR done after the queue drained
	std::chrono::steady_clock::time_point lastSendProgressAt;															// Meaningful only while the queue is not empty
	const std::array<uint8_t, 64>* networkSecret;
	std::vector<uint8_t> sessionKey;																					// Session key is negotiated during handshake

	// Frame crypto, created and keyed once when the handshake sets the session key — creating and keying these per frame
	// cost ~14 µs, far more than the cipher itself. The send side is shared by sender threads (encryptMutex); the receive
	// side has a single reader (I/O thread, or the handshake worker before it).
	void keyFrameCrypto();
	std::array<uint8_t, 8> frameHeaderMask(Botan::MessageAuthenticationCode& mac, std::span<const uint8_t> nonce) const;
	std::mutex encryptMutex;
	std::unique_ptr<Botan::AEAD_Mode> frameEncryptor;
	std::unique_ptr<Botan::MessageAuthenticationCode> sendHeaderMac;
	std::unique_ptr<Botan::AEAD_Mode> frameDecryptor;
	std::unique_ptr<Botan::MessageAuthenticationCode> receiveHeaderMac;
	std::shared_ptr<void> privateKey;																					// Only for client-node (that started connection)

	constexpr static uint8_t handshakeMaxPadding = 255;																	// Max padding for handshake request and reply
	constexpr static uint32_t bufferMinSize = 1024;																		// Frame buffer initial size
	constexpr static uint32_t bufferSoftLimit = 3145728;																// Frame buffer will shrink to this size (3MB) after receive large packet over bufferSoftLimit
	constexpr static uint32_t receiveReadAhead = 65536;																	// Max bytes read past the current frame in one receive() — bounds the buffer of small frames
	constexpr static uint32_t messageHardLimit = 16777216;																// Largest possible frame size (16MB) that can be transferred
};

} // namespace invilite::Mesh

#endif // MESH_CONNECTION_H