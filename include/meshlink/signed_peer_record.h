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

// Network endpoint where a peer can be reached.
// Serialization format on the wire:
//   addrType (1B) + addr (4B IPv4 | 16B IPv6) + port (2B BE)
struct PeerAddress {
    enum class Type : uint8_t {
        IPv4 = 0x01,
        IPv6 = 0x02,
    };

    Type         type = Type::IPv4;
    std::string  address;                                                           // textual form (e.g. "192.168.1.10", "fe80::1")
    uint16_t     port = 0;

    bool operator==(const PeerAddress& other) const {
        return this->type == other.type && this->port == other.port && this->address == other.address;
    }
};

// Self-attested record about a peer — created and signed by the peer itself,
// propagated through the mesh unchanged. Other peers verify the signature
// and trust the content without being able to modify it.
//
// Wire format (serialized for transmission and signing):
//   ed25519Pub     (32B)
//   x25519Pub      (32B)
//   createdAt      (8B BE, unix seconds)
//   addressCount   (1B)
//   addresses      (variable — each PeerAddress serialized as above)
//   signature      (64B) — Ed25519 over all preceding bytes
//
// peerId is not serialized — it is derived from (ed25519Pub || x25519Pub)
// and must match after deserialization.
struct SignedPeerRecord {
    PeerId                       peerId{};                                          // derived, not part of wire format
    std::vector<uint8_t>         ed25519Pub;                                        // 32B
    std::vector<uint8_t>         x25519Pub;                                         // 32B
    std::chrono::system_clock::time_point createdAt{};
    std::vector<PeerAddress>     addresses;
    std::vector<uint8_t>         signature;                                         // 64B Ed25519
};

// Outcome of deserialization / verification
enum class SignedRecordStatus : int {
    Success                = 0,
    MalformedEncoding      = -1,                                                    // truncated, bad addrType, etc.
    SignatureInvalid       = -3,                                                    // signature verification failed
    TimestampOutOfRange    = -4,                                                    // createdAt too far in the future (records never expire)
};

// Serialization / deserialization helpers.
// Kept as free functions because SignedPeerRecord is POD-like data with no behavior.
namespace SignedPeerRecordCodec {

    // Serialize the signed portion (without the signature) — used as input for signing.
    std::vector<uint8_t> serializeForSigning(
        std::span<const uint8_t> ed25519Pub,
        std::span<const uint8_t> x25519Pub,
        std::chrono::system_clock::time_point createdAt,
        const std::vector<PeerAddress>& addresses
    );

    // Serialize the full record (includes signature) for transmission.
    std::vector<uint8_t> serialize(const SignedPeerRecord& record);

    // Deserialize and verify a record received from the wire.
    // Populates outRecord on success. Records never expire; createdAt may lead local time by at most maxClockSkew.
    SignedRecordStatus deserialize(
        std::span<const uint8_t> data,
        SignedPeerRecord& outRecord,
        std::chrono::seconds maxClockSkew  = std::chrono::minutes(5)
    );

} // namespace SignedPeerRecordCodec

} // namespace invilite::Mesh

#endif // MESH_SIGNED_PEER_RECORD_H