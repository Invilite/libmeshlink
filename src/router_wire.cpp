#include "meshlink/router_wire.h"

#include <botan/ed25519.h>
#include <botan/pubkey.h>

#include <algorithm>
#include <string_view>

namespace invilite::Mesh::RouterWire {

namespace {
    constexpr std::string_view SIGNATURE_DOMAIN = "MeshLink-Router-V1";

    constexpr size_t  PEER_ID_SIZE          = 32;
    constexpr size_t  ED25519_PUB_SIZE      = 32;
    constexpr size_t  MAX_LIST_ENTRIES      = 255;                                  // 1-byte counts (source route, recorded route, ACK route)
    constexpr size_t  MAX_TLV_LENGTH        = 0xFFFF;                               // 2-byte TLV length and extensions total length

    constexpr uint8_t FLAG_KIND_MASK        = 0x03;
    constexpr uint8_t FLAG_RECORD_ROUTE     = 0x04;
    constexpr uint8_t FLAG_ACK_REQUESTED    = 0x08;
    constexpr uint8_t FLAG_HAS_EXTENSIONS   = 0x10;
    constexpr uint8_t FLAG_RESERVED_MASK    = 0xE0;

    constexpr uint8_t HIGHEST_MODE          = static_cast<uint8_t>(RoutingMode::Flood);
    constexpr uint8_t HIGHEST_KIND          = static_cast<uint8_t>(RoutedMessageKind::RouteError);

    // Extension types this node understands. Only matters for critical types (an unknown critical type rejects the
    // message); none exists yet. Unknown non-critical extensions are kept as received.
    constexpr uint8_t KNOWN_EXTENSION_TYPES[] = { EXTENSION_SENT_TO };

    bool isKnownExtensionType(uint8_t type) {
        return std::find(std::begin(KNOWN_EXTENSION_TYPES), std::end(KNOWN_EXTENSION_TYPES), type) != std::end(KNOWN_EXTENSION_TYPES);
    }

    void writeBE16(std::vector<uint8_t>& out, uint16_t v) {
        out.push_back(static_cast<uint8_t>(v >> 8));
        out.push_back(static_cast<uint8_t>(v));
    }

    void writeBE32(std::vector<uint8_t>& out, uint32_t v) {
        for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(v >> shift));
    }

    void writeBE64(std::vector<uint8_t>& out, uint64_t v) {
        for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(v >> shift));
    }

    void writePeerIds(std::vector<uint8_t>& out, const std::vector<PeerId>& ids) {
        for (const PeerId& id : ids) out.insert(out.end(), id.begin(), id.end());
    }

    void writeExtension(std::vector<uint8_t>& out, const RoutingExtension& extension) {
        out.push_back(extension.type);
        writeBE16(out, static_cast<uint16_t>(extension.value.size()));
        out.insert(out.end(), extension.value.begin(), extension.value.end());
    }

    // Bounds-checked sequential reader over a received span. Every read fails (returns false) instead of overrunning.
    class WireReader {
    public:
        explicit WireReader(std::span<const uint8_t> data) : data(data) {}

        size_t remaining() const { return data.size() - offset; }

        bool readBytes(size_t count, std::span<const uint8_t>& out) {
            if (count > remaining()) return false;
            out = data.subspan(offset, count);
            offset += count;
            return true;
        }

        bool readU8(uint8_t& out) {
            if (remaining() < 1) return false;
            out = data[offset++];
            return true;
        }

        bool readUnsignedBE(size_t width, uint64_t& out) {
            if (remaining() < width) return false;
            out = 0;
            for (size_t i = 0; i < width; ++i) out = (out << 8) | data[offset++];
            return true;
        }

        bool readPeerId(PeerId& out) {
            std::span<const uint8_t> bytes;
            if (!readBytes(PEER_ID_SIZE, bytes)) return false;
            std::copy(bytes.begin(), bytes.end(), out.begin());
            return true;
        }

        bool readPeerIds(size_t count, std::vector<PeerId>& out) {
            if (count > remaining() / PEER_ID_SIZE) return false;                   // check before allocating
            out.resize(count);
            for (PeerId& id : out) readPeerId(id);
            return true;
        }

    private:
        std::span<const uint8_t> data;
        size_t                   offset = 0;
    };

    uint8_t versionAndModeByte(const RoutedMessage& message) {
        return static_cast<uint8_t>(WIRE_VERSION << 4) | static_cast<uint8_t>(message.mode);
    }

    // Flags byte as signed: HAS_EXTENSIONS is not part of it (a relay may add a per-hop extension)
    uint8_t signedFlagsByte(const RoutedMessage& message) {
        uint8_t flags = static_cast<uint8_t>(message.kind) | static_cast<uint8_t>(message.reservedFlagBits & FLAG_RESERVED_MASK);
        if (message.recordedRoute)  flags |= FLAG_RECORD_ROUTE;
        if (message.ackRequested)   flags |= FLAG_ACK_REQUESTED;
        return flags;
    }

    size_t extensionsBlockLength(const RoutedMessage& message) {
        size_t length = 0;
        for (const RoutingExtension& extension : message.extensions) length += 1 + 2 + extension.value.size();
        return length;
    }

    // Structural consistency of a message about to be encoded — the same rules decode enforces, plus field-size limits.
    bool isEncodable(const RoutedMessage& message) {
        if (message.group > MAX_ROUTED_GROUP)                                       return false;
        if (static_cast<uint8_t>(message.mode) > HIGHEST_MODE)                      return false;
        if (static_cast<uint8_t>(message.kind) > HIGHEST_KIND)                      return false;
        if (message.mode == RoutingMode::Broadcast && message.kind != RoutedMessageKind::Data) return false;
        if ((message.reservedFlagBits & ~FLAG_RESERVED_MASK) != 0)                  return false;
        if (message.ttlInitial == 0 || message.ttlRemaining > message.ttlInitial)   return false;
        if (message.destination.has_value() != (message.mode != RoutingMode::Broadcast))    return false;
        if (message.sourceRoute.has_value() != (message.mode == RoutingMode::SourceRouted)) return false;
        if (message.sourceRoute) {
            if (message.sourceRoute->hops.size() > MAX_LIST_ENTRIES)                return false;
            if (message.sourceRoute->nextHopIndex > message.sourceRoute->hops.size()) return false;
        }
        if (message.recordedRoute && message.recordedRoute->size() > MAX_LIST_ENTRIES)  return false;
        for (const RoutingExtension& extension : message.extensions) {
            if (extension.value.size() > MAX_TLV_LENGTH)                            return false;
        }
        if (extensionsBlockLength(message) > MAX_TLV_LENGTH)                        return false;
        const size_t expectedSignatureSize = requiresSignature(message.mode, message.kind) ? SIGNATURE_SIZE : 0;
        return message.signature.size() == expectedSignatureSize;
    }

    // Kind-specific payload shape is part of the receive validation (3.6): a malformed ACK / ROUTE_ERROR is rejected
    // before anyone acts on it.
    bool hasValidKindPayload(const RoutedMessage& message) {
        if (message.kind == RoutedMessageKind::Ack)        { AckPayload ack;          return decodeAckPayload(message.payload, ack); }
        if (message.kind == RoutedMessageKind::RouteError) { RouteErrorPayload error; return decodeRouteErrorPayload(message.payload, error); }
        return true;
    }
}

bool requiresSignature(RoutingMode mode, RoutedMessageKind kind) {
    return mode == RoutingMode::Broadcast || kind == RoutedMessageKind::Ack || kind == RoutedMessageKind::RouteError;
}

std::vector<uint8_t> encode(const RoutedMessage& message) {
    if (!isEncodable(message)) return {};

    std::vector<uint8_t> out;
    out.reserve(3 + FIXED_HEADER_SIZE + 2 * PEER_ID_SIZE + extensionsBlockLength(message) + message.signature.size() + message.payload.size());

    // Layer 1 (Network)
    out.push_back(message.group);
    writeBE16(out, message.subtype);

    // Fixed part
    out.push_back(versionAndModeByte(message));
    out.push_back(signedFlagsByte(message) | (message.extensions.empty() ? 0 : FLAG_HAS_EXTENSIONS));
    out.push_back(message.ttlRemaining);
    out.push_back(message.ttlInitial);
    writeBE64(out, message.msgId);
    writeBE32(out, message.sentAtUnixSeconds);
    out.insert(out.end(), message.sender.begin(), message.sender.end());

    // Mode- and flag-dependent parts, in wire order
    if (message.destination) out.insert(out.end(), message.destination->begin(), message.destination->end());
    if (message.sourceRoute) {
        out.push_back(static_cast<uint8_t>(message.sourceRoute->hops.size()));
        out.push_back(message.sourceRoute->nextHopIndex);
        writePeerIds(out, message.sourceRoute->hops);
    }
    if (message.recordedRoute) {
        out.push_back(static_cast<uint8_t>(message.recordedRoute->size()));
        writePeerIds(out, *message.recordedRoute);
    }
    if (!message.extensions.empty()) {
        writeBE16(out, static_cast<uint16_t>(extensionsBlockLength(message)));
        for (const RoutingExtension& extension : message.extensions) writeExtension(out, extension);
    }
    out.insert(out.end(), message.signature.begin(), message.signature.end());
    out.insert(out.end(), message.payload.begin(), message.payload.end());
    return out;
}

RoutedMessageStatus decode(uint8_t group, uint16_t subtype, std::span<const uint8_t> body, std::chrono::system_clock::time_point now,
                           RoutedMessage& out, std::chrono::seconds maxClockSkew) {
    out = RoutedMessage{};
    if (group > MAX_ROUTED_GROUP) return RoutedMessageStatus::NotRoutedGroup;
    out.group   = group;
    out.subtype = subtype;

    WireReader reader(body);
    uint8_t versionAndMode = 0, flags = 0;
    uint64_t msgId = 0, sentAt = 0;
    if (!reader.readU8(versionAndMode) || !reader.readU8(flags) || !reader.readU8(out.ttlRemaining) || !reader.readU8(out.ttlInitial)
        || !reader.readUnsignedBE(8, msgId) || !reader.readUnsignedBE(4, sentAt) || !reader.readPeerId(out.sender)) {
        return RoutedMessageStatus::MalformedEncoding;
    }
    out.msgId             = msgId;
    out.sentAtUnixSeconds = static_cast<uint32_t>(sentAt);

    // Header semantics that need no further bytes — reject early
    if ((versionAndMode >> 4) != WIRE_VERSION)                      return RoutedMessageStatus::UnsupportedVersion;
    if ((versionAndMode & 0x0F) > HIGHEST_MODE)                     return RoutedMessageStatus::ReservedMode;
    if ((flags & FLAG_KIND_MASK) > HIGHEST_KIND)                    return RoutedMessageStatus::ReservedKind;
    out.mode             = static_cast<RoutingMode>(versionAndMode & 0x0F);
    out.kind             = static_cast<RoutedMessageKind>(flags & FLAG_KIND_MASK);
    out.ackRequested     = (flags & FLAG_ACK_REQUESTED) != 0;
    out.reservedFlagBits = flags & FLAG_RESERVED_MASK;
    if (out.mode == RoutingMode::Broadcast && out.kind != RoutedMessageKind::Data)  return RoutedMessageStatus::KindNotAllowedInMode;
    if (out.ttlInitial == 0 || out.ttlRemaining > out.ttlInitial)                   return RoutedMessageStatus::InvalidTtl;

    const auto sentAtTime = std::chrono::system_clock::time_point(std::chrono::seconds(out.sentAtUnixSeconds));
    if (sentAtTime > now + maxClockSkew || sentAtTime < now - maxClockSkew)         return RoutedMessageStatus::TimestampOutOfWindow;

    if (out.mode != RoutingMode::Broadcast) {
        PeerId destination{};
        if (!reader.readPeerId(destination)) return RoutedMessageStatus::MalformedEncoding;
        out.destination = destination;
    }

    if (out.mode == RoutingMode::SourceRouted) {
        uint8_t hopCount = 0;
        SourceRoute route;
        if (!reader.readU8(hopCount) || !reader.readU8(route.nextHopIndex) || !reader.readPeerIds(hopCount, route.hops)) return RoutedMessageStatus::MalformedEncoding;
        if (route.nextHopIndex > hopCount) return RoutedMessageStatus::SourceRouteIndexOutOfRange;
        out.sourceRoute = std::move(route);
    }

    if (flags & FLAG_RECORD_ROUTE) {
        uint8_t hopCount = 0;
        std::vector<PeerId> recorded;
        if (!reader.readU8(hopCount) || !reader.readPeerIds(hopCount, recorded)) return RoutedMessageStatus::MalformedEncoding;
        out.recordedRoute = std::move(recorded);
    }

    if (flags & FLAG_HAS_EXTENSIONS) {
        uint64_t blockLength = 0;
        std::span<const uint8_t> block;
        if (!reader.readUnsignedBE(2, blockLength) || !reader.readBytes(blockLength, block)) return RoutedMessageStatus::MalformedEncoding;

        WireReader blockReader(block);
        bool unknownCritical = false;
        while (blockReader.remaining() > 0) {
            RoutingExtension extension;
            uint64_t valueLength = 0;
            std::span<const uint8_t> value;
            if (!blockReader.readU8(extension.type) || !blockReader.readUnsignedBE(2, valueLength) || !blockReader.readBytes(valueLength, value)) {
                return RoutedMessageStatus::MalformedEncoding;                      // a TLV crossing the declared block end
            }
            extension.value.assign(value.begin(), value.end());
            unknownCritical |= extension.isCritical() && !isKnownExtensionType(extension.type);
            out.extensions.push_back(std::move(extension));
        }
        if (unknownCritical) return RoutedMessageStatus::UnknownCriticalExtension;  // after the whole block: framing errors take precedence
    }

    if (requiresSignature(out.mode, out.kind)) {
        std::span<const uint8_t> signature;
        if (!reader.readBytes(SIGNATURE_SIZE, signature)) return RoutedMessageStatus::MalformedEncoding;
        out.signature.assign(signature.begin(), signature.end());
    }

    std::span<const uint8_t> payload;
    reader.readBytes(reader.remaining(), payload);
    out.payload.assign(payload.begin(), payload.end());

    if (!hasValidKindPayload(out)) return RoutedMessageStatus::MalformedEncoding;
    return RoutedMessageStatus::Success;
}

std::vector<uint8_t> bytesToSign(const RoutedMessage& message) {
    std::vector<uint8_t> out;
    out.reserve(SIGNATURE_DOMAIN.size() + 3 + 15 + 2 * PEER_ID_SIZE + 2 + extensionsBlockLength(message) + message.payload.size());

    out.insert(out.end(), SIGNATURE_DOMAIN.begin(), SIGNATURE_DOMAIN.end());
    out.push_back(message.group);
    writeBE16(out, message.subtype);
    out.push_back(versionAndModeByte(message));
    out.push_back(signedFlagsByte(message));
    out.push_back(message.ttlInitial);
    writeBE64(out, message.msgId);
    writeBE32(out, message.sentAtUnixSeconds);
    out.insert(out.end(), message.sender.begin(), message.sender.end());
    if (message.destination) out.insert(out.end(), message.destination->begin(), message.destination->end());
    if (message.sourceRoute) {
        out.push_back(static_cast<uint8_t>(message.sourceRoute->hops.size()));
        writePeerIds(out, message.sourceRoute->hops);
    }

    std::vector<uint8_t> signedExtensions;
    for (const RoutingExtension& extension : message.extensions) {
        if (!extension.isPerHop()) writeExtension(signedExtensions, extension);
    }
    writeBE16(out, static_cast<uint16_t>(signedExtensions.size()));
    out.insert(out.end(), signedExtensions.begin(), signedExtensions.end());

    out.insert(out.end(), message.payload.begin(), message.payload.end());
    return out;
}

bool verifySignature(const RoutedMessage& message, std::span<const uint8_t> senderEd25519Pub) {
    if (message.signature.size() != SIGNATURE_SIZE || senderEd25519Pub.size() != ED25519_PUB_SIZE) return false;
    try {
        const Botan::Ed25519_PublicKey key(std::vector<uint8_t>(senderEd25519Pub.begin(), senderEd25519Pub.end()));
        Botan::PK_Verifier verifier(key, "Pure");
        const std::vector<uint8_t> signedBytes = bytesToSign(message);
        verifier.update(signedBytes.data(), signedBytes.size());
        return verifier.check_signature(message.signature.data(), message.signature.size());
    } catch (const std::exception&) {
        return false;                                                               // malformed key
    }
}

std::vector<uint8_t> encodeAckPayload(const AckPayload& ack) {
    if (ack.receivedRoute.size() > MAX_LIST_ENTRIES) return {};
    std::vector<uint8_t> out;
    out.reserve(8 + 1 + ack.receivedRoute.size() * PEER_ID_SIZE);
    writeBE64(out, ack.acknowledgedMsgId);
    out.push_back(static_cast<uint8_t>(ack.receivedRoute.size()));
    writePeerIds(out, ack.receivedRoute);
    return out;
}

bool decodeAckPayload(std::span<const uint8_t> payload, AckPayload& out) {
    WireReader reader(payload);
    uint8_t hopCount = 0;
    if (!reader.readUnsignedBE(8, out.acknowledgedMsgId) || !reader.readU8(hopCount) || !reader.readPeerIds(hopCount, out.receivedRoute)) return false;
    return reader.remaining() == 0;
}

std::vector<uint8_t> encodeRouteErrorPayload(const RouteErrorPayload& error) {
    std::vector<uint8_t> out;
    out.reserve(8 + PEER_ID_SIZE + 1);
    writeBE64(out, error.stuckMsgId);
    out.insert(out.end(), error.unreachableDestination.begin(), error.unreachableDestination.end());
    out.push_back(static_cast<uint8_t>(error.reason));
    return out;
}

bool decodeRouteErrorPayload(std::span<const uint8_t> payload, RouteErrorPayload& out) {
    WireReader reader(payload);
    uint8_t reason = 0;
    if (!reader.readUnsignedBE(8, out.stuckMsgId) || !reader.readPeerId(out.unreachableDestination) || !reader.readU8(reason)) return false;
    out.reason = static_cast<RouteErrorReason>(reason);
    return reader.remaining() == 0;
}

} // namespace invilite::Mesh::RouterWire
