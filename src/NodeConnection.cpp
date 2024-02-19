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

// TODO: Configure to use other elipic curves, f.e.: secp521r1, brainpoolP384r1, brainpoolP512r1
invilite::NodeConnection::NodeConnection(int clientSocket, const sockaddr_storage* clientAddress, const invilite::NodeId* nodeId, const SecByteBlock& networkSecret): clientSocket(clientSocket), nodeId(nodeId), clientAddress(*clientAddress), dh(secp256r1()), hmac(networkSecret, networkSecret.size()) {
	if (clientAddress->ss_family == AF_INET) {
	    // Przychodzące połączenie IPv4
	    const sockaddr_in* addr4 = reinterpret_cast<const sockaddr_in*>(clientAddress);
	    inet_ntop(AF_INET, &addr4->sin_addr, remoteClientAddress, sizeof(remoteClientAddress));
	    remoteClientPort = ntohs(addr4->sin_port);
	} else if (clientAddress->ss_family == AF_INET6) {
	    // Przychodzące połączenie IPv6
	    const sockaddr_in6* addr6 = reinterpret_cast<const sockaddr_in6*>(clientAddress);
	    inet_ntop(AF_INET6, &addr6->sin6_addr, remoteClientAddress, sizeof(remoteClientAddress));
	    remoteClientPort = ntohs(addr6->sin6_port);
	} else {
	    // Nieznany typ adresu
	}
}

const char* invilite::NodeConnection::getRemoteClientAddress() {
	return this->remoteClientAddress;
}

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
	spdlog::trace("[{}] Preparing handshake request ...", this->getRemoteClientAddress());

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

    spdlog::trace("[{}] Sending handshake request ...", this->getRemoteClientAddress());
    // Send message to remote client
    // message = nodeId[16] + pubKeyA + HMAC[networkSecret](nodeId + pubKeyA)
    if (this->sendRaw(message) != (ssize_t)message.size()) {
    	spdlog::trace("[{}] Unable to send handshake to server", this->getRemoteClientAddress());
    	return -1;
    }

	return 0;
}

int invilite::NodeConnection::waitForHandshake(uint8_t timeout) {
	spdlog::trace("[{}] Waiting for handshake ...", this->getRemoteClientAddress());

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
        	spdlog::trace("[{}] Handshake timeout after {} seconds", this->getRemoteClientAddress(), timeout);
            return -2;
        }

        // Receive incomming data
        ssize_t received = recv(clientSocket, message.data() + totalReceived, expectedLength - totalReceived, 0);
        if (received < 0) {
            spdlog::trace("[{}] Error receiving handshake data", this->getRemoteClientAddress());
            return -3;
        }
        totalReceived += received;
    }

    spdlog::trace("[{}] Handshake received", this->getRemoteClientAddress());

    // If connection doesn't have a private key yet, this is a server side, otherwise it's response from the server
    if (this->privKey.size() == 0) {
    	if (this->validateHandshake(&message) < 0) {
    		spdlog::trace("[{}] Unable to validate handshake", this->getRemoteClientAddress());
	    	return -4;
	    }
    } else {
    	if (this->finishHandshake(&message) < 0) {
    		spdlog::trace("[{}] Unable to finish handshake", this->getRemoteClientAddress());
	    	return -4;
	    }
    }


    return 0;
}

int invilite::NodeConnection::validateHandshake(const std::vector<uint8_t>* message) {
	const char* remoteClientAddress = this->getRemoteClientAddress();
	spdlog::trace("[{}] Starting handshake validation ...", remoteClientAddress);
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
    	spdlog::trace("[{}] Handshake signature invalid!", remoteClientAddress);
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
        spdlog::trace("[{}] Failed to agree on a shared secret", remoteClientAddress);
        return -2;
    }

	// Add pubKeyB as a part of a reply
    reply.insert(reply.end(), pubKeyB.BytePtr(), pubKeyB.BytePtr() + pubKeyB.SizeInBytes());

    // Calculate signature for reply
    std::vector<uint8_t> replySignature(this->hmac.DigestSize());
    this->hmac.CalculateDigest(signature.data(), reply.data(), reply.size());

    // Add calculated signature to message
    reply.insert(reply.end(), signature.begin(), signature.end());

    spdlog::trace("[{}] Sending handshake reply to client ...", remoteClientAddress);
    if (this->sendRaw(reply) != (ssize_t)reply.size()) {
    	spdlog::trace("[{}] Unable to send handshake reply to client", remoteClientAddress);
    	return -3;
    }

    // TODO: Remove this aftr tests
    std::string hexSecret = SecByteBlockToHex(sharedSecret);
    spdlog::trace("[{}] Shared secret: {}", remoteClientAddress, hexSecret);
    spdlog::trace("[{}] Validation successful", remoteClientAddress);

    return 0;
}

int invilite::NodeConnection::finishHandshake(const std::vector<uint8_t>* message) {
	spdlog::trace("[{}] Starting handshake validation ...", this->getRemoteClientAddress());
	std::vector<uint8_t> nodeId(message->begin(), message->begin() + 16);
    std::vector<uint8_t> pubKeyB(message->begin() + 16, message->begin() + 16 + this->dh.PublicKeyLength());
    std::vector<uint8_t> hmacSignature(message->end() - this->hmac.DigestSize(), message->end());

    // Calculate signature for handshake
    std::vector<uint8_t> signature(this->hmac.DigestSize());
    this->hmac.CalculateDigest(signature.data(), message->data(), message->size() - this->hmac.DigestSize());

    // Check if signature was valid
    if (hmacSignature != signature) {
    	spdlog::trace("[{}] Handshake signature invalid!", remoteClientAddress);
    	return -1;
    }

    // If signature was valid, we can trust that remote node id is valid
    std::copy(message->begin(), message->begin() + 16, remoteNodeId.begin());

    // Convert received public key from client to SecByteBlock
    SecByteBlock pubKeyServer(pubKeyB.data(), pubKeyB.size());

    // Calculate shared secret
    this->sharedSecret.resize(this->dh.AgreedValueLength());
    if (!this->dh.Agree(this->sharedSecret, this->privKey, pubKeyServer)) {
        spdlog::trace("[{}] Failed to agree on a shared secret", remoteClientAddress);
        return -2;
    }

    // TODO: Remove this after tests
    std::string hexSecret = SecByteBlockToHex(sharedSecret);
	spdlog::trace("[{}] Shared secret: {}", remoteClientAddress, hexSecret);
    spdlog::trace("[{}] Validation successful", remoteClientAddress);

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
	// Generate initialization vector (12 bytes)
	AutoSeededRandomPool prng;
	SecByteBlock iv(12);
    prng.GenerateBlock(iv, iv.size());

    // Poly1305 tag size is 16 bytes (128 bits)
    const size_t poly1305Length = 16;

    // Packet header length
    const uint8_t headerLength = 24;

    // Calculate total packet length (header length + encrypted data + checksum tag (Poly1305))
    const uint32_t packetLength = static_cast<uint32_t>(headerLength + data.size() + poly1305Length);

    // Create additional authenticated data (header)
    std::array<uint8_t, headerLength> packetHeader = this->createHeader(packetLength, iv);

    // Allocate space for the ciphertext and the Poly1305 tag
    std::vector<uint8_t> ciphertext(data.size());
    CryptoPP::SecByteBlock tag(poly1305Length);

    // Prepare ChaCha20-Poly1305 cipher
    ChaCha20Poly1305::Encryption cipher;
    cipher.SetKeyWithIV(this->sharedSecret, this->sharedSecret.size(), iv, iv.size());

    // Encrypt and authenticate (generate Poly1305 tag)
    cipher.EncryptAndAuthenticate(ciphertext.data(), tag, tag.size(), iv, iv.size(), packetHeader.data(), packetHeader.size(), data.data(), data.size());

    // Construct the final packet with AAD (header), encrypted data, and tag
    std::vector<uint8_t> packet(packetHeader.size() + ciphertext.size() + tag.size());
    std::memcpy(packet.data(), packetHeader.data(), packetHeader.size());
    std::memcpy(packet.data() + packetHeader.size(), ciphertext.data(), ciphertext.size());
    std::memcpy(packet.data() + packetHeader.size() + ciphertext.size(), tag.data(), tag.size());

    // TODO: Check if std::vector can be repleaced with std::array, std::array can be a little bit faster

    return packet;
}

const std::vector<uint8_t> invilite::NodeConnection::decryptData(const std::vector<uint8_t>& packet) {
	// Initialization vector size
	const uint32_t ivSize = 12;

	// Poly1305 tag size is 16 bytes (128 bits)
    const size_t poly1305Length = 16;

    // Packet header length
    const uint8_t headerLength = 24;

    // Total packet length
    uint32_t totalPacketLength;

    const uint32_t minPacketLength = (headerLength + poly1305Length);

    // Check if packed has minimum packet size for zero data packet (header + poly1305tag)
    if (packet.size() < minPacketLength) {
    	std::ostringstream oss;
    	oss << "Packet is damage, minimum " << minPacketLength << " bytes is required, but only " << packet.size() << " bytes found.";
        throw std::runtime_error(oss.str());
    }

    // Extract total packet length from header (and match it to real packet length)
    totalPacketLength = (packet[6] << 24) | (packet[7] << 16) | (packet[8] << 8) | packet[9];
    if (packet.size() != totalPacketLength) {
    	std::ostringstream oss;
    	oss << "Invalid packet length, expected " << totalPacketLength << " bytes, but " << packet.size() << " bytes found.";
        throw std::runtime_error(oss.str());
    }

    // Extract IV from packet
    CryptoPP::SecByteBlock iv(ivSize);
    std::memcpy(iv.data(), packet.data() + 12, ivSize);

    const size_t ciphertextSize = totalPacketLength - headerLength - poly1305Length;

    // Separate ciphertext and tag
    std::vector<uint8_t> ciphertext(ciphertextSize);
    std::memcpy(ciphertext.data(), packet.data() + headerLength, ciphertextSize);

    CryptoPP::SecByteBlock tag(poly1305Length);
    std::memcpy(tag.data(), packet.data() + headerLength + ciphertextSize, poly1305Length);

    // Prepare ChaCha20Poly1305 cipher
    CryptoPP::ChaCha20Poly1305::Decryption dec;
    dec.SetKeyWithIV(this->sharedSecret, this->sharedSecret.size(), iv, iv.size());

    // Create AAD from packet header
	std::vector<uint8_t> aad;
	aad.reserve(headerLength);
	aad.insert(aad.end(), packet.data(), packet.data() + headerLength);

    // Decrypt and verify
    std::vector<uint8_t> decryptedData(ciphertextSize);
    bool isValid = dec.DecryptAndVerify(decryptedData.data(), tag, tag.size(), iv, iv.size(), aad.data(), aad.size(), ciphertext.data(), ciphertextSize);

    if (!isValid) {
        throw std::runtime_error("Invalid authentication tag.");
    }

    return decryptedData;
}

const std::array<uint8_t, 24> invilite::NodeConnection::createHeader(uint32_t packetSize, const CryptoPP::SecByteBlock& iv) {
    std::array<uint8_t, 24> header;					// Reserve 24 bytes for header
    header[0] = 0x55;								// Magic number byte 1
    header[1] = 0xB4;								// Magic number byte 2
    header[2] = 0x88;								// Magic number byte 3
    header[3] = 0x01;								// Protocol version

    header[6] = (packetSize >> 24) & 0xFF;
    header[7] = (packetSize >> 16) & 0xFF;
    header[8] = (packetSize >> 8) & 0xFF;
    header[9] = packetSize & 0xFF;

    // Calculate CRC for first 10 bytes of header
    const uint16_t crc = calculateCRC16(header, 0, 10);

    // Add CRC checksum to header
    header[10] = crc >> 8;
    header[11] = crc & 0xFF;

    // Add IV to header
    std::copy(iv.begin(), iv.end(), header.begin() + 12);

    return header;
}

bool invilite::NodeConnection::verifyHeader(const std::vector<uint8_t>& data, uint32_t& packetSize, uint8_t& protocol) {
    // Check magic numbers
    if (data[0] != 0x55 || data[1] != 0xB4 || data[2] != 0x88) {
        return false;
    }

    // Calculate and verify CRC checksum for first 10 bytes of header
    const uint16_t expectedCRC = (data[10] << 8) | data[11];
    const uint16_t calculatedCRC = NodeConnection::calculateCRC16(std::vector<uint8_t>(data.begin(), data.begin() + 10));

    if (calculatedCRC != expectedCRC) {
        return false;
    }

    // Get protocol version number
    protocol = data[3];

    // Get packet size
    packetSize = (data[6] << 24) | (data[7] << 16) | (data[8] << 8) | data[9];

    return true;
}

uint16_t invilite::NodeConnection::calculateCRC16(const std::vector<uint8_t>& data) {
    uint16_t crc = 0x16AB;

    for (size_t i = 0; i < data.size(); ++i) {
        uint8_t index = (crc >> 8) ^ data[i];
        crc = crc16Table[index] ^ (crc << 8);
    }

    return crc;
}

uint16_t invilite::NodeConnection::calculateCRC16(const std::array<uint8_t, 24>& data, size_t start, size_t end) {
    uint16_t crc = 0x16AB;
    
    for (size_t i = start; i < end; ++i) {
        uint8_t index = (crc >> 8) ^ data[i];
        crc = crc16Table[index] ^ (crc << 8);
    }

    return crc;
}


std::string invilite::NodeConnection::SecByteBlockToHex(const CryptoPP::SecByteBlock& block) {
    CryptoPP::HexEncoder encoder;
    std::string output;

    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(block.BytePtr(), block.SizeInBytes());
    encoder.MessageEnd();

    return output;
}
