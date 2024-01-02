#ifndef NODE_CONNECTION_H
#define NODE_CONNECTION_H

// #include <set>
// #include <mutex>
// #include <atomic>
#include <array>
#include <string>
#include <vector>
// #include <memory>
// #include <thread>
// #include <utility>
// #include <unistd.h>
#include <iostream>
#include <sys/uio.h>
// #include <algorithm>
// #include <functional>
//#include <cstring>
// #include <iostream>
#include <unistd.h>
#include <sys/socket.h>


#include <cryptopp/sha3.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

#include <cryptopp/osrng.h>

#include <cryptopp/eccrypto.h>
using CryptoPP::ECDH;
using CryptoPP::DL_GroupParameters_EC;

#include <cryptopp/oids.h>
using CryptoPP::OID;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include "ClientId.h"

using CryptoPP::ECP;
using CryptoPP::byte;
using CryptoPP::ECDH;
using CryptoPP::HMAC;
using CryptoPP::SHA3_256;
using CryptoPP::SecByteBlock;
using CryptoPP::AutoSeededRandomPool;
using namespace CryptoPP::ASN1;

namespace invilite {

class NodeConnection {
public:
	NodeConnection(int clientSocket, const invilite::ClientId* nodeId, const std::vector<uint32_t> networkSecretKey);
	void close();

	int getSocket();
	int initHandshake();
	int waitForHandshake(uint8_t timeout = 3);
	int validateHandshake(const std::vector<uint8_t>* message);
	int finishHandshake(const std::vector<uint8_t>* message);

	ssize_t send(const std::string& data);
    ssize_t send(const std::vector<uint8_t>& data);
    ssize_t send(const uint8_t* data, uint32_t dataLen);
    ssize_t sendRaw(const std::vector<uint8_t>& data);

protected:
	int clientSocket;
	const invilite::ClientId* nodeId;

private:
	const std::vector<uint32_t> networkSecretKey;

	// Diffie-Hellman key exchange
	SecByteBlock sharedSecret;
	SecByteBlock privKey;		// Only for node that started connection

	static const std::array<uint16_t, 256> crc16Table;
    static std::array<uint16_t, 256> generateCRC16Table();
    static uint16_t calculateCRC16(const std::vector<uint8_t>& data);
    std::string SecByteBlockToHex(const CryptoPP::SecByteBlock& block);
};

} // namespace invilite

#endif // NODE_CONNECTION_H