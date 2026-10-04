#pragma once

#include "meshlink/identity.h"
#include "meshlink/signed_peer_record.h"

#include <chrono>
#include <vector>

namespace invilite::Mesh::TestHelpers {

// Build a record signed by `identity` with an arbitrary createdAt — LocalIdentity::buildSelfRecord
// always stamps "now", tests need to produce stale and future-dated records as well.
inline SignedPeerRecord makeSignedRecord(const LocalIdentity& identity, const std::vector<PeerAddress>& addresses, std::chrono::system_clock::time_point createdAt) {
    SignedPeerRecord rec;
    rec.peerId     = identity.getPeerId();
    rec.ed25519Pub = identity.getEd25519Pub();
    rec.x25519Pub  = identity.getX25519Pub();
    rec.createdAt  = std::chrono::time_point_cast<std::chrono::seconds>(createdAt);         // wire format has second precision
    rec.addresses  = addresses;
    rec.signature  = identity.sign(SignedPeerRecordCodec::serializeForSigning(rec.ed25519Pub, rec.x25519Pub, rec.createdAt, rec.addresses));
    return rec;
}

inline PeerAddress ipv4(const char* address, uint16_t port) { return { PeerAddress::Type::IPv4, address, port }; }
inline PeerAddress ipv6(const char* address, uint16_t port) { return { PeerAddress::Type::IPv6, address, port }; }

} // namespace invilite::Mesh::TestHelpers
