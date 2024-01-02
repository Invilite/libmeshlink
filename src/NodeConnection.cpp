#include "NodeConnection.h"

const std::array<uint16_t, 256> invilite::NodeConnection::crc16Table = invilite::NodeConnection::generateCRC16Table();

invilite::NodeConnection::NodeConnection(int clientSocket, const invilite::ClientId* nodeId, const std::vector<uint32_t> networkSecretKey): clientSocket(clientSocket), nodeId(nodeId), networkSecretKey(networkSecretKey) {}

void invilite::NodeConnection::close() {
	::shutdown(this->clientSocket, SHUT_RDWR);
    ::close(this->clientSocket);
    this->clientSocket = -1;
}

int invilite::NodeConnection::getSocket() {
	return this->clientSocket;
}

int invilite::NodeConnection::initHandshake() {
	// message = nodeId + pubKeyA + HMAC(nodeId + pubKeyA + secretNetworkPassword)

	// Create message to send (get this node id)
    std::vector<uint8_t> message = this->nodeId->getContentAsBytes();

	// Generate Elliptic-curve Diffie–Hellman key pair
	AutoSeededRandomPool rng;
    ECDH<ECP>::Domain dhA(secp256r1());
    this->privKey = SecByteBlock(dhA.PrivateKeyLength());
    SecByteBlock pubKeyA(dhA.PublicKeyLength());
    dhA.GenerateKeyPair(rng, this->privKey, pubKeyA);

    // Add pubKeyA as a part of a message
    message.insert(message.end(), pubKeyA.BytePtr(), pubKeyA.BytePtr() + pubKeyA.SizeInBytes());

    // Use networkSecretKey as HMAC key
    SecByteBlock key(reinterpret_cast<const byte*>(networkSecretKey.data()), networkSecretKey.size() * sizeof(uint32_t));

    // Calculate signature for handshake
	HMAC<SHA3_256> hmac(key, key.size());
    std::vector<uint8_t> signature(hmac.DigestSize());
    hmac.CalculateDigest(signature.data(), message.data(), message.size());

    // Add calculated signature to message
    message.insert(message.end(), signature.begin(), signature.end());

    if (this->sendRaw(message) != (ssize_t)message.size()) {
    	return -1;
    }

	return 0;
}

int invilite::NodeConnection::waitForHandshake(uint8_t timeout) {
	std::vector<uint8_t> message;
	message.resize(113);
	size_t expectedLength = 113;

	size_t totalReceived = 0;
    while (totalReceived < expectedLength) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(clientSocket, &readfds);

        // Set timeout
        struct timeval tv;
        tv.tv_sec = timeout;
        tv.tv_usec = 0;

        // Wait for data with timeout
        int selectResult = select(clientSocket + 1, &readfds, NULL, NULL, &tv);

        if (selectResult < 0) {
        	std::cout << "Error in select()" << std::endl << std::flush;
        	return -1;
        } else if (selectResult == 0) {
            std::cout << "Handshake timeout" << std::endl << std::flush;
            return -2;
        }

        // Incomming data
        ssize_t received = recv(clientSocket, message.data() + totalReceived, expectedLength - totalReceived, 0);
        if (received < 0) {
            std::cout << "Error receiving data" << std::endl << std::flush;
            return -3;
        }
        totalReceived += received;
    }

    // If connection doesn't have a private key yet, this is a server side
    if (this->privKey.size() == 0) {
    	if (this->validateHandshake(&message) < 0) {
	    	return -4;
	    }
    } else {
    	if (this->finishHandshake(&message) < 0) {
	    	return -4;
	    }
    }


    return 0;
}

int invilite::NodeConnection::validateHandshake(const std::vector<uint8_t>* message) {
	// message = nodeId + pubKeyB + HMAC(nodeId + pubKeyB + secretNetworkPassword)

	// Create reply to send (get this node id)
    std::vector<uint8_t> reply = this->nodeId->getContentAsBytes();

	std::vector<uint8_t> nodeId(message->begin(), message->begin() + 16);
    std::vector<uint8_t> pubKeyA(message->begin() + 16, message->begin() + 16 + 65);
    std::vector<uint8_t> hmacSignature(message->end() - 32, message->end());

    // Use networkSecretKey as HMAC key
    SecByteBlock key(reinterpret_cast<const byte*>(networkSecretKey.data()), networkSecretKey.size() * sizeof(uint32_t));

    // Calculate signature for handshake
	HMAC<SHA3_256> hmac(key, key.size());
    std::vector<uint8_t> signature(hmac.DigestSize());
    hmac.CalculateDigest(signature.data(), message->data(), message->size() - 32);

    // Check if signature was valid
    if (hmacSignature != signature) {
    	std::cout << "Signature mismatch!" << std::endl << std::flush;
    	return -1;
    }

	// Generate Elliptic-curve Diffie–Hellman key pair
	AutoSeededRandomPool rng;
    ECDH<ECP>::Domain dhB(secp256r1());
    SecByteBlock privKeyB(dhB.PrivateKeyLength());
    SecByteBlock pubKeyB(dhB.PublicKeyLength());
    dhB.GenerateKeyPair(rng, privKeyB, pubKeyB);

    // Convert received public key from client to SecByteBlock
    SecByteBlock pubKeyClient(pubKeyA.data(), pubKeyA.size());

    // Calculate shared secret
    this->sharedSecret.resize(dhB.AgreedValueLength());
    if (!dhB.Agree(this->sharedSecret, privKeyB, pubKeyClient)) {
        std::cout << "Failed to agree on a shared secret" << std::endl << std::flush;
        return -2;
    }

	// Add pubKeyB as a part of a reply
    reply.insert(reply.end(), pubKeyB.BytePtr(), pubKeyB.BytePtr() + pubKeyB.SizeInBytes());

    // Calculate signature for reply
    std::vector<uint8_t> replySignature(hmac.DigestSize());
    hmac.CalculateDigest(signature.data(), reply.data(), reply.size());

    // Add calculated signature to message
    reply.insert(reply.end(), signature.begin(), signature.end());

    if (this->sendRaw(reply) != (ssize_t)reply.size()) {
    	return -3;
    }

    std::string hexSecret = SecByteBlockToHex(sharedSecret);
	std::cout << "Shared secret (hex): " << hexSecret << std::endl;

    return 0;
}

int invilite::NodeConnection::finishHandshake(const std::vector<uint8_t>* message) {
	std::vector<uint8_t> nodeId(message->begin(), message->begin() + 16);
    std::vector<uint8_t> pubKeyB(message->begin() + 16, message->begin() + 16 + 65);
    std::vector<uint8_t> hmacSignature(message->end() - 32, message->end());

    // Use networkSecretKey as HMAC key
    SecByteBlock key(reinterpret_cast<const byte*>(networkSecretKey.data()), networkSecretKey.size() * sizeof(uint32_t));

    // Calculate signature for handshake
	HMAC<SHA3_256> hmac(key, key.size());
    std::vector<uint8_t> signature(hmac.DigestSize());
    hmac.CalculateDigest(signature.data(), message->data(), message->size() - 32);

    // Check if signature was valid
    if (hmacSignature != signature) {
    	std::cout << "Signature mismatch!" << std::endl << std::flush;
    	return -1;
    }

    // Convert received public key from client to SecByteBlock
    SecByteBlock pubKeyServer(pubKeyB.data(), pubKeyB.size());

    // Calculate shared secret
    ECDH<ECP>::Domain dhA(secp256r1());
    this->sharedSecret.resize(dhA.AgreedValueLength());
    if (!dhA.Agree(this->sharedSecret, this->privKey, pubKeyServer)) {
        std::cout << "Failed to agree on a shared secret" << std::endl << std::flush;
        return -2;
    }

    std::string hexSecret = SecByteBlockToHex(sharedSecret);
	std::cout << "Shared secret (hex): " << hexSecret << std::endl;

    return 0;
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
        std::cerr << "Error: socket is closed." << std::endl;
        return -1;
    }

    const uint8_t  headerSize = 5;
    const uint32_t packetSize = headerSize + packetData.size() + 2; // Header size, data size and crc size
    const uint16_t crc = invilite::NodeConnection::calculateCRC16(packetData);
    std::vector<uint8_t> packetHeader;
    packetHeader.reserve(headerSize);

    // Add packet header
    packetHeader.push_back(0x01);   // Packet type
    for (int i = 3; i >= 0; --i) {
        packetHeader.push_back(static_cast<uint8_t>((packetSize >> (8 * i)) & 0xFF));
    }

    // Join all buffers (without data copying)
    struct iovec iov[3];
    iov[0].iov_base = (void*) packetHeader.data();
    iov[0].iov_len = packetHeader.size();
    iov[1].iov_base = (void*) packetData.data();
    iov[1].iov_len = packetData.size();
    iov[2].iov_base = (void*)&crc;
    iov[2].iov_len = sizeof(crc);

    // Send data
    ssize_t sentBytes = ::writev(clientSocket, iov, 3);
    if (sentBytes != (ssize_t)packetSize) {
        std::cerr << "Error: not all bytes were sent" << std::endl;
    }

    return sentBytes;
}

ssize_t invilite::NodeConnection::sendRaw(const std::vector<uint8_t>& data) {
	if (this->clientSocket == -1) {
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

std::array<uint16_t, 256> invilite::NodeConnection::generateCRC16Table() {
    std::array<uint16_t, 256> table;
    const uint16_t polynomial = 0x1021; // Wielomian dla CRC-16-CCITT.

    for (uint16_t i = 0; i < 256; i++) {
        uint16_t value = i << 8;

        for (uint8_t j = 0; j < 8; j++) {
            if (value & 0x8000) {
                value = (value << 1) ^ polynomial;
            } else {
                value <<= 1;
            }
        }

        table[i] = value;
    }

    return table;
}

uint16_t invilite::NodeConnection::calculateCRC16(const std::vector<uint8_t>& data) {
    uint16_t crc = 0xFFFF;

    for (uint8_t byte : data) {
        uint8_t index = (crc >> 8) ^ byte;
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
