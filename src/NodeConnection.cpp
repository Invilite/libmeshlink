#include "NodeConnection.h"

/**
char addressBuffer[INET6_ADDRSTRLEN];
uint16_t port;

if (clientAddress->ss_family == AF_INET) {
    // Przychodzące połączenie IPv4
    const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(clientAddress);
    inet_ntop(AF_INET, &addr4->sin_addr, addressBuffer, sizeof(addressBuffer));
    port = ntohs(addr4->sin_port);
    spdlog::debug("onConnect: Incomming IPv4 connection from {} on port {}", addressBuffer, port);
} else if (clientAddress->ss_family == AF_INET6) {
    // Przychodzące połączenie IPv6
    const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(clientAddress);
    inet_ntop(AF_INET6, &addr6->sin6_addr, addressBuffer, sizeof(addressBuffer));
    port = ntohs(addr6->sin6_port);
    spdlog::debug("onConnect: Incomming IPv6 connection from {} on port {}", addressBuffer, port);
} else {
    // Nieznany typ adresu
    spdlog::error("onConnect: Incomming connection unknown address family");
}
 */

// TODO: Configure to use other elipic curves, f.e.: secp521r1, brainpoolP384r1, brainpoolP512r1
invilite::NodeConnection::NodeConnection(int clientSocket, const sockaddr_storage* clientAddress, const invilite::NodeId* nodeId, const SecByteBlock& networkSecret): clientSocket(clientSocket), nodeId(nodeId), clientAddress(*clientAddress), dh(secp256r1()), hmac(networkSecret, networkSecret.size()) {}

void invilite::NodeConnection::close() {
	if (this->clientSocket != -1) {
		::shutdown(this->clientSocket, SHUT_RDWR);
    	::close(this->clientSocket);
    	this->clientSocket = -1;
	}
}

int invilite::NodeConnection::getSocket() const {
	return this->clientSocket;
}

int invilite::NodeConnection::initHandshake() {
	spdlog::trace("initHandshake: Generating handshake request ...");

	// Create message to send (get this node id)
    std::vector<uint8_t> message = this->nodeId->getContentAsBytes();

	// Generate Elliptic-curve Diffie–Hellman key pair
	AutoSeededRandomPool rng;
	SecByteBlock pubKeyA(this->dh.PublicKeyLength());
    this->privKey = SecByteBlock(this->dh.PrivateKeyLength());
    this->dh.GenerateKeyPair(rng, this->privKey, pubKeyA);

    // Add pubKeyA as a part of a message
    message.insert(message.end(), pubKeyA.BytePtr(), pubKeyA.BytePtr() + pubKeyA.SizeInBytes());

    // Calculate signature for handshake
    std::vector<uint8_t> signature(this->hmac.DigestSize());
    this->hmac.CalculateDigest(signature.data(), message.data(), message.size());

    // Add calculated signature to message
    message.insert(message.end(), signature.begin(), signature.end());

    spdlog::trace("initHandshake: Sending handshake request ...");

    // Send message to remote client
    // message = nodeId[16] + pubKeyA + HMAC[networkSecret](nodeId + pubKeyA)
    if (this->sendRaw(message) != (ssize_t)message.size()) {
    	spdlog::debug("initHandshake: Unable to send handshake to server");
    	return -1;
    }

	return 0;
}

int invilite::NodeConnection::waitForHandshake(uint8_t timeout) {
	spdlog::trace("waitForHandshake: Waiting for handshake ...");

	// message = nodeId[16] + pubKeyA + HMAC[networkSecret](nodeId + pubKeyA)
	const size_t expectedLength = 16 + this->dh.PublicKeyLength() + this->hmac.DigestSize();

	// Buffer for incomming message
	std::vector<uint8_t> message(expectedLength);

	size_t totalReceived = 0;
    while (totalReceived < expectedLength) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(clientSocket, &readfds);

        // Set timeout
        struct timeval tv;
        tv.tv_sec = timeout;
        tv.tv_usec = 0;

        // Wait for incomming data to be ready (with timeout)
        int selectResult = select(clientSocket + 1, &readfds, NULL, NULL, &tv);

        if (selectResult < 0) {
        	spdlog::debug("waitForHandshake: Error in select()");
        	return -1;
        } else if (selectResult == 0) {
            spdlog::debug("waitForHandshake: Handshake timeout after {} seconds", timeout);
            return -2;
        }

        // Receive incomming data
        ssize_t received = recv(clientSocket, message.data() + totalReceived, expectedLength - totalReceived, 0);
        if (received < 0) {
            spdlog::debug("waitForHandshake: Error receiving data");
            return -3;
        }
        totalReceived += received;
    }

    spdlog::trace("waitForHandshake: Handshake received");

    // If connection doesn't have a private key yet, this is a server side, otherwise it's response from the server
    if (this->privKey.size() == 0) {
    	if (this->validateHandshake(&message) < 0) {
    		spdlog::debug("waitForHandshake: Unable to validate handshake");
	    	return -4;
	    }
    } else {
    	if (this->finishHandshake(&message) < 0) {
    		spdlog::debug("waitForHandshake: Unable to finish handshake");
	    	return -4;
	    }
    }


    return 0;
}

int invilite::NodeConnection::validateHandshake(const std::vector<uint8_t>* message) {
	spdlog::trace("validateHandshake: Starting handshake validation ...");
	// message = nodeId + pubKeyB + HMAC(nodeId + pubKeyB + secretNetworkPassword)

	// Create reply to send (get this node id)
    std::vector<uint8_t> reply = this->nodeId->getContentAsBytes();

	std::vector<uint8_t> nodeId(message->begin(), message->begin() + 16);
    std::vector<uint8_t> pubKeyA(message->begin() + 16, message->begin() + 16 + this->dh.PublicKeyLength());
    std::vector<uint8_t> hmacSignature(message->end() - this->hmac.DigestSize(), message->end());

    // Calculate signature for handshake
    std::vector<uint8_t> signature(this->hmac.DigestSize());
    this->hmac.CalculateDigest(signature.data(), message->data(), message->size() - this->hmac.DigestSize());

    // Check if signature was valid
    if (hmacSignature != signature) {
    	spdlog::debug("validateHandshake: Signature mismatch!");
    	return -1;
    }

    // If signature was valid, we can trust that remote node id is valid
    std::copy(message->begin(), message->begin() + 16, remoteNodeId.begin());

	// Generate Elliptic-curve Diffie–Hellman key pair
	AutoSeededRandomPool rng;
    SecByteBlock privKeyB(this->dh.PrivateKeyLength());
    SecByteBlock pubKeyB(this->dh.PublicKeyLength());
    this->dh.GenerateKeyPair(rng, privKeyB, pubKeyB);

    // Convert received public key from client to SecByteBlock
    SecByteBlock pubKeyClient(pubKeyA.data(), pubKeyA.size());

    // Calculate shared secret
    this->sharedSecret.resize(this->dh.AgreedValueLength());
    if (!this->dh.Agree(this->sharedSecret, privKeyB, pubKeyClient)) {
        spdlog::debug("validateHandshake: Failed to agree on a shared secret");
        return -2;
    }

	// Add pubKeyB as a part of a reply
    reply.insert(reply.end(), pubKeyB.BytePtr(), pubKeyB.BytePtr() + pubKeyB.SizeInBytes());

    // Calculate signature for reply
    std::vector<uint8_t> replySignature(this->hmac.DigestSize());
    this->hmac.CalculateDigest(signature.data(), reply.data(), reply.size());

    // Add calculated signature to message
    reply.insert(reply.end(), signature.begin(), signature.end());

    spdlog::debug("validateHandshake: Sending handshake reply to client ...");
    if (this->sendRaw(reply) != (ssize_t)reply.size()) {
    	spdlog::debug("validateHandshake: Unable to send handshake reply to client");
    	return -3;
    }

    // TODO: Remove this aftr tests
    std::string hexSecret = SecByteBlockToHex(sharedSecret);
    spdlog::trace("validateHandshake: Shared secret (hex): {}", hexSecret);

	spdlog::trace("validateHandshake: Validation successful");

    return 0;
}

int invilite::NodeConnection::finishHandshake(const std::vector<uint8_t>* message) {
	spdlog::trace("finishHandshake: Starting handshake validation ...");
	std::vector<uint8_t> nodeId(message->begin(), message->begin() + 16);
    std::vector<uint8_t> pubKeyB(message->begin() + 16, message->begin() + 16 + this->dh.PublicKeyLength());
    std::vector<uint8_t> hmacSignature(message->end() - this->hmac.DigestSize(), message->end());

    // Calculate signature for handshake
    std::vector<uint8_t> signature(this->hmac.DigestSize());
    this->hmac.CalculateDigest(signature.data(), message->data(), message->size() - this->hmac.DigestSize());

    // Check if signature was valid
    if (hmacSignature != signature) {
    	spdlog::debug("finishHandshake: Signature mismatch!");
    	return -1;
    }

    // If signature was valid, we can trust that remote node id is valid
    std::copy(message->begin(), message->begin() + 16, remoteNodeId.begin());

    // Convert received public key from client to SecByteBlock
    SecByteBlock pubKeyServer(pubKeyB.data(), pubKeyB.size());

    // Calculate shared secret
    this->sharedSecret.resize(this->dh.AgreedValueLength());
    if (!this->dh.Agree(this->sharedSecret, this->privKey, pubKeyServer)) {
        spdlog::debug("finishHandshake: Failed to agree on a shared secret");
        return -2;
    }

    // TODO: Remove this after tests
    std::string hexSecret = SecByteBlockToHex(sharedSecret);
	spdlog::trace("finishHandshake: Shared secret (hex): {}", hexSecret);

	spdlog::trace("finishHandshake: Validation successful");

    return 0;
}

const std::array<uint8_t, 16> invilite::NodeConnection::getRemoteNodeId() const {
	return this->remoteNodeId;
}

ssize_t invilite::NodeConnection::send(const std::string& data) {
    std::vector<uint8_t> vector(data.begin(), data.end());
    return this->send(vector);
}

ssize_t invilite::NodeConnection::send(const uint8_t* rawData, uint32_t dataLen) {
    std::vector<uint8_t> data(rawData, rawData + dataLen);
    return this->send(data);
}

ssize_t invilite::NodeConnection::send(const std::vector<uint8_t>& packetData) {
    if (clientSocket == -1) {
    	// Socket is closed
        return -1;
    }

    const uint8_t  headerSize = 4;
    const uint32_t packetSize = headerSize + packetData.size();
    std::vector<uint8_t> packetHeader;
    packetHeader.reserve(headerSize);

    // Add packet header
    for (int i = 3; i >= 0; --i) {
        packetHeader.push_back(static_cast<uint8_t>((packetSize >> (8 * i)) & 0xFF));
    }

    // Join all buffers (without data copying) - packetHeader + packetData
    struct iovec iov[2];
    iov[0].iov_base = (void*) packetHeader.data();
    iov[0].iov_len = packetHeader.size();
    iov[1].iov_base = (void*) packetData.data();
    iov[1].iov_len = packetData.size();

    // Send data
    ssize_t sentBytes = ::writev(clientSocket, iov, 2);
    if (sentBytes != (ssize_t)packetSize) {
        spdlog::error("Unable to send data: not all bytes were sent");
    }

    return sentBytes;
}

ssize_t invilite::NodeConnection::sendRaw(const std::vector<uint8_t>& data) {
	if (this->clientSocket == -1) {
		// Socket is closed
        return -1;
    }

    ssize_t totalSent = 0;
    ssize_t bytesLeft = data.size();
    ssize_t n;

    while (totalSent < bytesLeft) {
        n = ::send(this->clientSocket, data.data() + totalSent, bytesLeft, 0);
        if (n == -1) { break; }
        totalSent += n;
        bytesLeft -= n;
    }

    // Return -1 on error, total bytes send otherwise
    return (n == -1) ? -1 : totalSent;
}

const std::vector<uint8_t> invilite::NodeConnection::encryptData(const std::vector<uint8_t>& data) {
	// Generate initialization vector
	AutoSeededRandomPool prng;
	SecByteBlock iv(12);
    prng.GenerateBlock(iv, iv.size());

    // Poly1305 tag size is 16 bytes (128 bits)
    const size_t poly1305size = 16;

    // Calculate total packet length (length + IV + encrypted data + checksum tag (Poly1305))
    const uint32_t packetLength = static_cast<uint32_t>(sizeof(uint32_t) + iv.size() + data.size() + poly1305size);

    // Create additional authenticated data from packet length and IV
    std::vector<uint8_t> aad(sizeof(packetLength) + iv.size());
    std::memcpy(aad.data(), &packetLength, sizeof(packetLength));
    std::memcpy(aad.data() + sizeof(packetLength), iv.data(), iv.size());

    // Allocate space for the ciphertext and the Poly1305 tag
    std::vector<uint8_t> ciphertext(data.size());
    CryptoPP::SecByteBlock tag(poly1305size);

    // Prepare ChaCha20-Poly1305 cipher
    ChaCha20Poly1305::Encryption cipher;
    cipher.SetKeyWithIV(this->sharedSecret, this->sharedSecret.size(), iv, iv.size());

    // Encrypt and authenticate (generate Poly1305 tag)
    cipher.EncryptAndAuthenticate(ciphertext.data(), tag, tag.size(), iv, iv.size(), aad.data(), aad.size(), data.data(), data.size());

    // Construct the final packet with AAD, encrypted data, and tag
    std::vector<uint8_t> packet(aad.size() + ciphertext.size() + tag.size());
    std::memcpy(packet.data(), aad.data(), aad.size());
    std::memcpy(packet.data() + aad.size(), ciphertext.data(), ciphertext.size());
    std::memcpy(packet.data() + aad.size() + ciphertext.size(), tag.data(), tag.size());

    // TODO: Check if std::vector can be repleaced with std::array

    return packet;
}

const std::vector<uint8_t> invilite::NodeConnection::decryptData(const std::vector<uint8_t>& packet) {
	// Initialization vector size
	const uint32_t ivSize = 12;

	// Poly1305 tag size is 16 bytes (128 bits)
    const size_t poly1305size = 16;

    // Total packet length
    uint32_t totalPacketLength;

    const uint32_t minPacketLength = (sizeof(totalPacketLength) + ivSize + poly1305size);

    // Check if packed has minimum packet size for zero data packet (header + iv + poly1305tag)
    if (packet.size() < minPacketLength) {
    	std::ostringstream oss;
    	oss << "Packet is damage, minimum " << minPacketLength << " bytes is required, but only " << packet.size() << " bytes found.";
        throw std::runtime_error(oss.str());
    }

    // Extract total packet length from header (and match it to real packet length)
    std::memcpy(&totalPacketLength, packet.data(), sizeof(totalPacketLength));
    if (packet.size() != totalPacketLength) {
    	std::ostringstream oss;
    	oss << "Invalid packet length, expected " << totalPacketLength << " bytes, but " << packet.size() << " bytes found.";
        throw std::runtime_error(oss.str());
    }

    // Extract IV from packet
    CryptoPP::SecByteBlock iv(ivSize);
    std::memcpy(iv.data(), packet.data() + sizeof(totalPacketLength), ivSize);

    const size_t ciphertextSize = totalPacketLength - sizeof(totalPacketLength) - ivSize - poly1305size;

    // Separate ciphertext and tag
    std::vector<uint8_t> ciphertext(ciphertextSize);
    std::memcpy(ciphertext.data(), packet.data() + sizeof(totalPacketLength) + ivSize, ciphertextSize);

    CryptoPP::SecByteBlock tag(poly1305size);
    std::memcpy(tag.data(), packet.data() + sizeof(totalPacketLength) + ivSize + ciphertextSize, poly1305size);

    // Prepare ChaCha20Poly1305 cipher
    CryptoPP::ChaCha20Poly1305::Decryption dec;
    dec.SetKeyWithIV(this->sharedSecret, this->sharedSecret.size(), iv, iv.size());

    // Create AAD from packet length and IV
    // TODO: Use data from "packet"
    std::vector<uint8_t> aad(sizeof(totalPacketLength) + iv.size());
    std::memcpy(aad.data(), &totalPacketLength, sizeof(totalPacketLength));
    std::memcpy(aad.data() + sizeof(totalPacketLength), iv.data(), iv.size());

    // Decrypt and verify
    std::vector<uint8_t> decryptedData(ciphertextSize);
    bool isValid = dec.DecryptAndVerify(decryptedData.data(), tag, tag.size(), iv, iv.size(), aad.data(), aad.size(), ciphertext.data(), ciphertextSize);

    if (!isValid) {
        throw std::runtime_error("Invalid authentication tag.");
    }

    return decryptedData;
}

std::string invilite::NodeConnection::SecByteBlockToHex(const CryptoPP::SecByteBlock& block) {
    CryptoPP::HexEncoder encoder;
    std::string output;

    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(block.BytePtr(), block.SizeInBytes());
    encoder.MessageEnd();

    return output;
}
