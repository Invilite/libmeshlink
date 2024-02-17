#ifndef NODE_CONNECTION_H
#define NODE_CONNECTION_H

#include <array>
#include <string>
#include <vector>
#include <iostream>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <spdlog/spdlog.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha3.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/chacha.h>
#include <cryptopp/filters.h>
#include <cryptopp/poly1305.h>
#include <cryptopp/secblock.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/chachapoly.h>
#include "NodeId.h"

using CryptoPP::OID;
using CryptoPP::ECP;
using CryptoPP::byte;
using CryptoPP::ECDH;
using CryptoPP::HMAC;
using CryptoPP::SHA3_256;
using CryptoPP::SecByteBlock;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::DL_GroupParameters_EC;
using namespace CryptoPP::ASN1;
using namespace CryptoPP;

namespace invilite {

class NodeConnection {
public:
	NodeConnection(int clientSocket, const sockaddr_storage* clientAddress, const invilite::NodeId* nodeId, const SecByteBlock& networkSecret);
	void close();
	int getSocket() const;
	int initHandshake();
	int waitForHandshake(uint8_t timeout = 5);
	int validateHandshake(const std::vector<uint8_t>* message);
	int finishHandshake(const std::vector<uint8_t>* message);
	const std::array<uint8_t, 16> getRemoteNodeId() const;
	const std::vector<uint8_t> encryptData(const std::vector<uint8_t>& data);
	const std::vector<uint8_t> decryptData(const std::vector<uint8_t>& packet);

	ssize_t send(const std::string& data);
    ssize_t send(const std::vector<uint8_t>& data);
    ssize_t send(const uint8_t* data, uint32_t dataLen);

protected:
	int clientSocket;
	std::array<uint8_t, 16> remoteNodeId;
	const invilite::NodeId* nodeId;
	const sockaddr_storage clientAddress;
	ssize_t sendRaw(const std::vector<uint8_t>& data);

private:
	// Elliptic-curve Diffie-Hellman key exchange
	const ECDH<ECP>::Domain dh;
	SecByteBlock sharedSecret;
	SecByteBlock privKey;		// Only for node that started connection

	// Hash-based message authentication code (HMAC)
	HMAC<SHA3_256> hmac;

    std::string SecByteBlockToHex(const CryptoPP::SecByteBlock& block);
};

} // namespace invilite

#endif // NODE_CONNECTION_H