#pragma once

#ifndef MESH_SIGNED_PEER_RECORD_H
#define MESH_SIGNED_PEER_RECORD_H

#include "meshlink/peer_identity.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace invilite::Mesh {

// Network endpoint where a peer can be reached. Wire format:
//   addrType (1B) + addr (4B IPv4 | 16B IPv6) + port (2B BE)
struct PeerAddress {
    enum class Type : uint8_t {
        IPv4 = 0x01,
        IPv6 = 0x02,
    };

    Type         type = Type::IPv4;
    std::string  address;
    uint16_t     port = 0;

    bool operator==(const PeerAddress& other) const {
        return this->type == other.type && this->port == other.port && this->address == other.address;
    }
};

// Record about a peer, created and signed by the peer itself and passed on unchanged.
//
// Wire format (also the signed bytes):
//   ed25519Pub     (32B)
//   x25519Pub      (32B)
//   createdAt      (8B BE, unix seconds)
//   addressCount   (1B)
//   addresses      (each PeerAddress as above)
//   signature      (64B Ed25519 over all preceding bytes)
//
// peerId is not serialized: it is derived from (ed25519Pub || x25519Pub).
struct SignedPeerRecord {
    PeerId                       peerId{};
    std::vector<uint8_t>         ed25519Pub;
    std::vector<uint8_t>         x25519Pub;
    std::chrono::system_clock::time_point createdAt{};
    std::vector<PeerAddress>     addresses;
    std::vector<uint8_t>         signature;
};

enum class SignedRecordStatus : int {
    Success                = 0,
    MalformedEncoding      = -1,
    SignatureInvalid       = -3,
    TimestampOutOfRange    = -4,
};

namespace SignedPeerRecordCodec {

    // The bytes that get signed (everything except the signature).
    std::vector<uint8_t> serializeForSigning(
        std::span<const uint8_t> ed25519Pub,
        std::span<const uint8_t> x25519Pub,
        std::chrono::system_clock::time_point createdAt,
        const std::vector<PeerAddress>& addresses
    );

    std::vector<uint8_t> serialize(const SignedPeerRecord& record);

    // Verifies the signature and peerId. Records never expire; createdAt may lead local time by at most maxClockSkew.
    SignedRecordStatus deserialize(
        std::span<const uint8_t> data,
        SignedPeerRecord& outRecord,
        std::chrono::seconds maxClockSkew  = std::chrono::minutes(5)
    );

} // namespace SignedPeerRecordCodec

} // namespace invilite::Mesh

#endif // MESH_SIGNED_PEER_RECORD_H