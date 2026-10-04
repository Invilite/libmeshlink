#include "meshlink/signed_peer_record.h"
#include "meshlink/identity.h"

#include <botan/ed25519.h>
#include <botan/pubkey.h>

#include <arpa/inet.h>

#include <algorithm>
#include <cstring>

namespace invilite::Mesh::SignedPeerRecordCodec {

namespace {
    constexpr size_t ED25519_PUB_SIZE   = 32;
    constexpr size_t X25519_PUB_SIZE    = 32;
    constexpr size_t SIGNATURE_SIZE     = 64;
    constexpr size_t CREATED_AT_SIZE    = 8;
    constexpr size_t ADDR_COUNT_SIZE    = 1;
    constexpr size_t ADDR_TYPE_SIZE     = 1;
    constexpr size_t IPV4_BYTES         = 4;
    constexpr size_t IPV6_BYTES         = 16;
    constexpr size_t PORT_SIZE          = 2;
    constexpr uint8_t MAX_ADDRESSES     = 8;                                        // sanity cap — a peer announcing more is suspicious

    // Serialize one PeerAddress: addrType(1B) + addr(4B|16B) + port(2B BE)
    bool writeAddress(std::vector<uint8_t>& out, const PeerAddress& addr) {
        out.push_back(static_cast<uint8_t>(addr.type));

        if (addr.type == PeerAddress::Type::IPv4) {
            in_addr a4{};
            if (::inet_pton(AF_INET, addr.address.c_str(), &a4) != 1) return false;
            const auto* p = reinterpret_cast<const uint8_t*>(&a4);
            out.insert(out.end(), p, p + IPV4_BYTES);
        } else if (addr.type == PeerAddress::Type::IPv6) {
            in6_addr a6{};
            if (::inet_pton(AF_INET6, addr.address.c_str(), &a6) != 1) return false;
            const auto* p = reinterpret_cast<const uint8_t*>(&a6);
            out.insert(out.end(), p, p + IPV6_BYTES);
        } else {
            return false;
        }

        out.push_back(static_cast<uint8_t>((addr.port >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(addr.port & 0xFF));
        return true;
    }

    // Read one PeerAddress; advances offset. Returns false on any error.
    bool readAddress(std::span<const uint8_t> data, size_t& offset, PeerAddress& out) {
        if (offset + ADDR_TYPE_SIZE > data.size()) return false;
        const auto type = static_cast<PeerAddress::Type>(data[offset]);
        offset += ADDR_TYPE_SIZE;

        if (type == PeerAddress::Type::IPv4) {
            if (offset + IPV4_BYTES + PORT_SIZE > data.size()) return false;
            char buf[INET_ADDRSTRLEN];
            in_addr a4{};
            std::memcpy(&a4, data.data() + offset, IPV4_BYTES);
            if (::inet_ntop(AF_INET, &a4, buf, sizeof(buf)) == nullptr) return false;
            out.type    = PeerAddress::Type::IPv4;
            out.address = buf;
            offset += IPV4_BYTES;
        } else if (type == PeerAddress::Type::IPv6) {
            if (offset + IPV6_BYTES + PORT_SIZE > data.size()) return false;
            char buf[INET6_ADDRSTRLEN];
            in6_addr a6{};
            std::memcpy(&a6, data.data() + offset, IPV6_BYTES);
            if (::inet_ntop(AF_INET6, &a6, buf, sizeof(buf)) == nullptr) return false;
            out.type    = PeerAddress::Type::IPv6;
            out.address = buf;
            offset += IPV6_BYTES;
        } else {
            return false;                                                           // unknown addrType
        }

        out.port = (static_cast<uint16_t>(data[offset]) << 8) | static_cast<uint16_t>(data[offset + 1]);
        offset += PORT_SIZE;
        return true;
    }

    void writeBE64(std::vector<uint8_t>& out, uint64_t v) {
        for (int i = 7; i >= 0; --i) out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }

    uint64_t readBE64(std::span<const uint8_t> data, size_t offset) {
        uint64_t v = 0;
        for (size_t i = 0; i < 8; ++i) v = (v << 8) | data[offset + i];
        return v;
    }
}

std::vector<uint8_t> serializeForSigning(
    std::span<const uint8_t> ed25519Pub,
    std::span<const uint8_t> x25519Pub,
    std::chrono::system_clock::time_point createdAt,
    const std::vector<PeerAddress>& addresses)
{
    std::vector<uint8_t> out;
    out.reserve(ED25519_PUB_SIZE + X25519_PUB_SIZE + CREATED_AT_SIZE + ADDR_COUNT_SIZE + addresses.size() * 23);

    out.insert(out.end(), ed25519Pub.begin(), ed25519Pub.end());
    out.insert(out.end(), x25519Pub.begin(),  x25519Pub.end());

    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(
        createdAt.time_since_epoch()).count();
    writeBE64(out, static_cast<uint64_t>(secs));

    const uint8_t count = static_cast<uint8_t>(std::min<size_t>(addresses.size(), MAX_ADDRESSES));
    out.push_back(count);

    for (uint8_t i = 0; i < count; ++i) {
        if (!writeAddress(out, addresses[i])) {
            // Invalid address — produce empty vector to signal failure upstream
            return {};
        }
    }

    return out;
}

std::vector<uint8_t> serialize(const SignedPeerRecord& record) {
    std::vector<uint8_t> out = serializeForSigning(
        record.ed25519Pub, record.x25519Pub, record.createdAt, record.addresses
    );
    if (out.empty()) return {};

    out.insert(out.end(), record.signature.begin(), record.signature.end());
    return out;
}

SignedRecordStatus deserialize(
    std::span<const uint8_t> data,
    SignedPeerRecord& outRecord,
    std::chrono::seconds maxAge,
    std::chrono::seconds maxClockSkew)
{
    size_t offset = 0;

    // Fixed-size prefix: keys + timestamp + addrCount
    if (data.size() < ED25519_PUB_SIZE + X25519_PUB_SIZE + CREATED_AT_SIZE + ADDR_COUNT_SIZE) {
        return SignedRecordStatus::MalformedEncoding;
    }

    outRecord.ed25519Pub.assign(data.begin() + offset, data.begin() + offset + ED25519_PUB_SIZE);
    offset += ED25519_PUB_SIZE;
    outRecord.x25519Pub.assign(data.begin() + offset, data.begin() + offset + X25519_PUB_SIZE);
    offset += X25519_PUB_SIZE;

    const uint64_t secs = readBE64(data, offset);
    offset += CREATED_AT_SIZE;
    outRecord.createdAt = std::chrono::system_clock::time_point(std::chrono::seconds(secs));

    const uint8_t addrCount = data[offset];
    offset += ADDR_COUNT_SIZE;

    if (addrCount > MAX_ADDRESSES) {
        return SignedRecordStatus::MalformedEncoding;
    }

    outRecord.addresses.clear();
    outRecord.addresses.reserve(addrCount);
    for (uint8_t i = 0; i < addrCount; ++i) {
        PeerAddress addr;
        if (!readAddress(data, offset, addr)) {
            return SignedRecordStatus::MalformedEncoding;
        }
        outRecord.addresses.push_back(std::move(addr));
    }

    // Signature follows the signed portion
    if (offset + SIGNATURE_SIZE != data.size()) {
        return SignedRecordStatus::MalformedEncoding;                               // extra junk or missing signature
    }
    outRecord.signature.assign(data.begin() + offset, data.end());

    // ── Verify PeerId — derived from (ed25519Pub || x25519Pub) ──────────────
    outRecord.peerId = LocalIdentity::derivePeerId(outRecord.ed25519Pub, outRecord.x25519Pub);

    // ── Verify timestamp freshness ──────────────────────────────────────────
    const auto now = std::chrono::system_clock::now();
    if (outRecord.createdAt > now + maxClockSkew) {
        return SignedRecordStatus::TimestampOutOfRange;                             // too far in future
    }
    if (now - outRecord.createdAt > maxAge) {
        return SignedRecordStatus::TimestampOutOfRange;                             // too old
    }

    // ── Verify Ed25519 signature over signed portion ────────────────────────
    try {
        const Botan::Ed25519_PublicKey key(outRecord.ed25519Pub);
        Botan::PK_Verifier verifier(key, "Pure");

        const std::vector<uint8_t> signedBytes = serializeForSigning(
            outRecord.ed25519Pub, outRecord.x25519Pub, outRecord.createdAt, outRecord.addresses
        );
        if (signedBytes.empty()) return SignedRecordStatus::MalformedEncoding;

        verifier.update(signedBytes.data(), signedBytes.size());
        if (!verifier.check_signature(outRecord.signature.data(), outRecord.signature.size())) {
            return SignedRecordStatus::SignatureInvalid;
        }
    } catch (const std::exception&) {
        return SignedRecordStatus::SignatureInvalid;
    }

    return SignedRecordStatus::Success;
}

} // namespace invilite::Mesh::SignedPeerRecordCodec