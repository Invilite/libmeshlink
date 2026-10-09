#include "meshlink/router_wire.h"
#include "wire_bytes.h"

#include <botan/ed25519.h>
#include <botan/pubkey.h>

#include <algorithm>
#include <string_view>

namespace invilite::Mesh::RouterWire {

using WireBytes::WireReader;
using WireBytes::writeBE16;
using WireBytes::writeBE32;
using WireBytes::writeBE64;
using WireBytes::PEER_ID_SIZE;

namespace {
    constexpr std::string_view SIGNATURE_DOMAIN = "MeshLink-Router-V1";

    constexpr size_t  ED25519_PUB_SIZE      = 32;
    constexpr size_t  MAX_LIST_ENTRIES      = 255;                                  // 1-byte count of the source route
    constexpr size_t  MAX_TLV_LENGTH        = 0xFFFF;                               // 2-byte TLV length and extensions total length

    constexpr uint8_t FLAG_ACK_REQUESTED    = 0x01;
    constexpr uint8_t FLAG_HAS_EXTENSIONS   = 0x02;
    constexpr uint8_t FLAG_RESERVED_MASK    = 0xFC;

    constexpr uint8_t HIGHEST_MODE          = static_cast<uint8_t>(RoutingMode::Unicast);

    // Extension types this node understands. Only matters for critical types (an unknown critical type rejects the
    // message); none exists yet. Unknown non-critical extensions are kept as received.
    constexpr uint8_t KNOWN_EXTENSION_TYPES[] = { EXTENSION_SENT_TO };

    bool isKnownExtensionType(uint8_t type) {
        return std::find(std::begin(KNOWN_EXTENSION_TYPES), std::end(KNOWN_EXTENSION_TYPES), type) != std::end(KNOWN_EXTENSION_TYPES);
    }

    void writePeerIds(std::vector<uint8_t>& out, const std::vector<PeerId>& ids) {
        for (const PeerId& id : ids) out.insert(out.end(), id.begin(), id.end());
    }

    void writeExtension(std::vector<uint8_t>& out, const RoutingExtension& extension) {
        out.push_back(extension.type);
        writeBE16(out, static_cast<uint16_t>(extension.value.size()));
        out.insert(out.end(), extension.value.begin(), extension.value.end());
    }

    uint8_t versionAndModeByte(const RoutedMessage& message) {
        return static_cast<uint8_t>(WIRE_VERSION << 4) | static_cast<uint8_t>(message.mode);
    }

    // Flags byte as signed: HAS_EXTENSIONS is not part of it (a relay may add a per-hop extension)
    uint8_t signedFlagsByte(const RoutedMessage& message) {
        uint8_t flags = message.reservedFlagBits & FLAG_RESERVED_MASK;
        if (message.ackRequested) flags |= FLAG_ACK_REQUESTED;
        return flags;
    }

    size_t extensionsBlockLength(const RoutedMessage& message) {
        size_t length = 0;
        for (const RoutingExtension& extension : message.extensions) length += 1 + 2 + extension.value.size();
        return length;
    }

    // Structural consistency of a message about to be encoded: the same rules decode enforces, plus field-size limits.
    bool isEncodable(const RoutedMessage& message) {
        if (!carriesRoutingHeader(message.group, message.subtype))                  return false;
        if (static_cast<uint8_t>(message.mode) > HIGHEST_MODE)                      return false;
        if (message.group == ROUTER_PROTOCOL_GROUP && reachesEveryNode(message.mode) != travelsToEveryNode(message.subtype)) return false;
        if ((message.reservedFlagBits & ~FLAG_RESERVED_MASK) != 0)                  return false;
        if (message.ttlInitial == 0 || message.ttlRemaining > message.ttlInitial)   return false;
        if (message.destination.has_value() == reachesEveryNode(message.mode))      return false;
        if (message.sourceRoute.has_value() != (message.mode == RoutingMode::Routed)) return false;
        if (message.sourceRoute) {
            if (message.sourceRoute->hops.size() > MAX_LIST_ENTRIES)                return false;
            if (message.sourceRoute->nextHopIndex > message.sourceRoute->hops.size()) return false;
        }
        for (const RoutingExtension& extension : message.extensions) {
            if (extension.value.size() > MAX_TLV_LENGTH)                            return false;
        }
        if (extensionsBlockLength(message) > MAX_TLV_LENGTH)                        return false;
        const size_t expectedSignatureSize = requiresSignature(message.group, message.mode) ? SIGNATURE_SIZE : 0;
        return message.signature.size() == expectedSignatureSize;
    }

    constexpr size_t  MESSAGE_KEY_SIZE      = PEER_ID_SIZE + 8;                     // sender + msgId

    std::vector<uint8_t> controlFrameHeader(uint16_t subtype, size_t payloadSize) {
        std::vector<uint8_t> out;
        out.reserve(3 + payloadSize);
        out.push_back(ROUTER_PROTOCOL_GROUP);
        writeBE16(out, subtype);
        return out;
    }

    // IHAVE / GRAFT: count(1) + count x (sender(32) + msgId(8))
    std::vector<uint8_t> encodeKeyList(uint16_t subtype, std::span<const RoutedMessageKey> keys) {
        std::vector<uint8_t> out = controlFrameHeader(subtype, 1 + keys.size() * MESSAGE_KEY_SIZE);
        out.push_back(static_cast<uint8_t>(keys.size()));
        for (const RoutedMessageKey& key : keys) {
            out.insert(out.end(), key.sender.begin(), key.sender.end());
            writeBE64(out, key.msgId);
        }
        return out;
    }

    bool decodeKeyList(std::span<const uint8_t> payload, std::vector<RoutedMessageKey>& out) {
        WireReader reader(payload);
        uint8_t count = 0;
        if (!reader.readU8(count) || reader.remaining() != count * MESSAGE_KEY_SIZE) return false;
        out.resize(count);
        for (RoutedMessageKey& key : out) {
            reader.readPeerId(key.sender);
            reader.readUnsignedBE(8, key.msgId);
        }
        return true;
    }

    // The payload shape of a routed Router message is part of the receive validation: a malformed ACK / ROUTE_ERROR
    // is rejected before anyone acts on it. Unknown subtypes pass (a relay forwards what it does not understand).
    bool hasValidRouterMessagePayload(const RoutedMessage& message) {
        if (message.group != ROUTER_PROTOCOL_GROUP) return true;
        if (message.subtype == SUBTYPE_ACK)         { AckPayload ack;          return decodeAckPayload(message.payload, ack); }
        if (message.subtype == SUBTYPE_ROUTE_ERROR) { RouteErrorPayload error; return decodeRouteErrorPayload(message.payload, error); }
        if (message.subtype == SUBTYPE_RECORD_ROUTE)  { RecordRoutePayload probe; return decodeRecordRoutePayload(message.payload, probe); }
        if (message.subtype == SUBTYPE_ROUTE_REPORT)  { RouteReportPayload report; return decodeRouteReportPayload(message.payload, report); }
        if (message.subtype == SUBTYPE_PRESENCE || message.subtype == SUBTYPE_TREE_BEACON) return message.payload.empty();
        return true;
    }
}

bool reachesEveryNode(RoutingMode mode) {
    return mode == RoutingMode::Flood || mode == RoutingMode::Broadcast;
}

bool carriesRoutingHeader(uint8_t group, uint16_t subtype) {
    if (group <= MAX_ROUTED_GROUP) return true;
    return group == ROUTER_PROTOCOL_GROUP && subtype >= FIRST_ROUTED_ROUTER_SUBTYPE && subtype <= LAST_ROUTED_ROUTER_SUBTYPE;
}

bool requiresSignature(uint8_t group, RoutingMode mode) {
    return reachesEveryNode(mode) || group == ROUTER_PROTOCOL_GROUP;
}

size_t encodedSize(const RoutedMessage& message) {
    size_t size = 3 + FIXED_HEADER_SIZE + message.signature.size() + message.payload.size();
    if (message.destination) size += PEER_ID_SIZE;
    if (message.sourceRoute) size += 2 + message.sourceRoute->hops.size() * PEER_ID_SIZE;
    if (!message.extensions.empty()) size += 2 + extensionsBlockLength(message);
    return size;
}

std::vector<uint8_t> encode(const RoutedMessage& message) {
    if (!isEncodable(message)) return {};

    std::vector<uint8_t> out;
    out.reserve(3 + FIXED_HEADER_SIZE + 2 * PEER_ID_SIZE + extensionsBlockLength(message) + message.signature.size() + message.payload.size());

    out.push_back(message.group);
    writeBE16(out, message.subtype);

    out.push_back(versionAndModeByte(message));
    out.push_back(signedFlagsByte(message) | (message.extensions.empty() ? 0 : FLAG_HAS_EXTENSIONS));
    out.push_back(message.ttlRemaining);
    out.push_back(message.ttlInitial);
    writeBE64(out, message.msgId);
    writeBE32(out, message.sentAtUnixSeconds);
    out.insert(out.end(), message.sender.begin(), message.sender.end());

    if (message.destination) out.insert(out.end(), message.destination->begin(), message.destination->end());
    if (message.sourceRoute) {
        out.push_back(static_cast<uint8_t>(message.sourceRoute->hops.size()));
        out.push_back(message.sourceRoute->nextHopIndex);
        writePeerIds(out, message.sourceRoute->hops);
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
    if (!carriesRoutingHeader(group, subtype)) return RoutedMessageStatus::NotRoutedGroup;
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

    if ((versionAndMode >> 4) != WIRE_VERSION)                      return RoutedMessageStatus::UnsupportedVersion;
    out.mode             = static_cast<RoutingMode>(versionAndMode & 0x0F);
    out.ackRequested     = (flags & FLAG_ACK_REQUESTED) != 0;
    out.reservedFlagBits = flags & FLAG_RESERVED_MASK;
    if ((versionAndMode & 0x0F) > HIGHEST_MODE)                                     return RoutedMessageStatus::UnknownMode;
    if (group == ROUTER_PROTOCOL_GROUP && travelsToEveryNode(subtype)) {
        if (!reachesEveryNode(out.mode))                                            return RoutedMessageStatus::PresenceToOneNode;
    } else if (group == ROUTER_PROTOCOL_GROUP && reachesEveryNode(out.mode))        return RoutedMessageStatus::RouterMessageToEveryNode;
    if (out.ttlInitial == 0 || out.ttlRemaining > out.ttlInitial)                   return RoutedMessageStatus::InvalidTtl;

    const auto sentAtTime = std::chrono::system_clock::time_point(std::chrono::seconds(out.sentAtUnixSeconds));
    if (sentAtTime > now + maxClockSkew || sentAtTime < now - maxClockSkew)         return RoutedMessageStatus::TimestampOutOfWindow;

    if (!reachesEveryNode(out.mode)) {
        PeerId destination{};
        if (!reader.readPeerId(destination)) return RoutedMessageStatus::MalformedEncoding;
        out.destination = destination;
    }

    if (out.mode == RoutingMode::Routed) {
        uint8_t hopCount = 0;
        SourceRoute route;
        if (!reader.readU8(hopCount) || !reader.readU8(route.nextHopIndex) || !reader.readPeerIds(hopCount, route.hops)) return RoutedMessageStatus::MalformedEncoding;
        if (route.nextHopIndex > hopCount) return RoutedMessageStatus::SourceRouteIndexOutOfRange;
        out.sourceRoute = std::move(route);
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
                return RoutedMessageStatus::MalformedEncoding;
            }
            extension.value.assign(value.begin(), value.end());
            unknownCritical |= extension.isCritical() && !isKnownExtensionType(extension.type);
            out.extensions.push_back(std::move(extension));
        }
        if (unknownCritical) return RoutedMessageStatus::UnknownCriticalExtension;  // after the whole block: framing errors take precedence
    }

    if (requiresSignature(out.group, out.mode)) {
        std::span<const uint8_t> signature;
        if (!reader.readBytes(SIGNATURE_SIZE, signature)) return RoutedMessageStatus::MalformedEncoding;
        out.signature.assign(signature.begin(), signature.end());
    }

    std::span<const uint8_t> payload;
    reader.readBytes(reader.remaining(), payload);
    out.payload.assign(payload.begin(), payload.end());

    if (!hasValidRouterMessagePayload(out)) return RoutedMessageStatus::MalformedEncoding;
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

    const bool isProbe = message.group == ROUTER_PROTOCOL_GROUP && message.subtype == SUBTYPE_RECORD_ROUTE;
    const size_t signedPayload = isProbe ? std::min(message.payload.size(), RECORD_ROUTE_SIGNED_PREFIX) : message.payload.size();
    out.insert(out.end(), message.payload.begin(), message.payload.begin() + static_cast<std::ptrdiff_t>(signedPayload));
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
        return false;
    }
}

std::vector<uint8_t> encodeAckPayload(const AckPayload& ack) {
    std::vector<uint8_t> out;
    out.reserve(8);
    writeBE64(out, ack.acknowledgedMsgId);
    return out;
}

bool decodeAckPayload(std::span<const uint8_t> payload, AckPayload& out) {
    WireReader reader(payload);
    if (!reader.readUnsignedBE(8, out.acknowledgedMsgId)) return false;
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

namespace {
    constexpr size_t ROUTE_HOP_SIZE = PEER_ID_SIZE + 4;

    void writeRouteHops(std::vector<uint8_t>& out, const std::vector<RouteHop>& hops) {
        out.push_back(static_cast<uint8_t>(hops.size()));
        for (const RouteHop& hop : hops) {
            out.insert(out.end(), hop.node.begin(), hop.node.end());
            writeBE32(out, hop.offsetMs);
        }
    }

    // count(1) + count x hop, up to the end of the payload
    bool readRouteHops(WireReader& reader, std::vector<RouteHop>& out) {
        uint8_t count = 0;
        if (!reader.readU8(count) || reader.remaining() != count * ROUTE_HOP_SIZE) return false;
        out.resize(count);
        for (RouteHop& hop : out) {
            uint64_t offset = 0;
            reader.readPeerId(hop.node);
            reader.readUnsignedBE(4, offset);
            hop.offsetMs = static_cast<uint32_t>(offset);
        }
        return true;
    }
}

std::vector<uint8_t> encodeRecordRoutePayload(const RecordRoutePayload& probe) {
    if (probe.hops.size() > MAX_LIST_ENTRIES) return {};
    std::vector<uint8_t> out;
    writeBE64(out, probe.sentAtUnixMs);
    writeRouteHops(out, probe.hops);
    return out;
}

bool decodeRecordRoutePayload(std::span<const uint8_t> payload, RecordRoutePayload& out) {
    WireReader reader(payload);
    return reader.readUnsignedBE(8, out.sentAtUnixMs) && readRouteHops(reader, out.hops);
}

std::vector<uint8_t> encodeRouteReportPayload(const RouteReportPayload& report) {
    if (report.hops.size() > MAX_LIST_ENTRIES) return {};
    std::vector<uint8_t> out;
    writeBE64(out, report.probeMsgId);
    writeBE64(out, report.probeSentAtUnixMs);
    writeBE32(out, report.receivedOffsetMs);
    writeRouteHops(out, report.hops);
    return out;
}

bool decodeRouteReportPayload(std::span<const uint8_t> payload, RouteReportPayload& out) {
    WireReader reader(payload);
    uint64_t receivedOffset = 0;
    if (!reader.readUnsignedBE(8, out.probeMsgId) || !reader.readUnsignedBE(8, out.probeSentAtUnixMs) || !reader.readUnsignedBE(4, receivedOffset)) return false;
    out.receivedOffsetMs = static_cast<uint32_t>(receivedOffset);
    return readRouteHops(reader, out.hops);
}

std::vector<uint8_t> encodeIhave(std::span<const RoutedMessageKey> keys) {
    if (keys.empty() || keys.size() > MAX_KEYS_PER_CONTROL_MESSAGE) return {};
    return encodeKeyList(SUBTYPE_IHAVE, keys);
}

bool decodeIhave(std::span<const uint8_t> payload, std::vector<RoutedMessageKey>& out) {
    return decodeKeyList(payload, out) && !out.empty();
}

std::vector<uint8_t> encodeGraft(std::span<const RoutedMessageKey> keys) {
    if (keys.size() > MAX_KEYS_PER_CONTROL_MESSAGE) return {};
    return encodeKeyList(SUBTYPE_GRAFT, keys);
}

bool decodeGraft(std::span<const uint8_t> payload, std::vector<RoutedMessageKey>& out) {
    return decodeKeyList(payload, out);
}

std::vector<uint8_t> encodePrune() {
    return controlFrameHeader(SUBTYPE_PRUNE, 0);
}

bool decodePrune(std::span<const uint8_t> payload) {
    return payload.empty();
}

std::vector<uint8_t> encodeUnknownDeliveryMode(const UnknownDeliveryModeReport& report) {
    std::vector<uint8_t> out = controlFrameHeader(SUBTYPE_UNKNOWN_DELIVERY_MODE, 1 + MESSAGE_KEY_SIZE);
    out.push_back(report.mode);
    out.insert(out.end(), report.message.sender.begin(), report.message.sender.end());
    writeBE64(out, report.message.msgId);
    return out;
}

bool decodeUnknownDeliveryMode(std::span<const uint8_t> payload, UnknownDeliveryModeReport& out) {
    WireReader reader(payload);
    if (!reader.readU8(out.mode) || !reader.readPeerId(out.message.sender) || !reader.readUnsignedBE(8, out.message.msgId)) return false;
    return reader.remaining() == 0;
}

} // namespace invilite::Mesh::RouterWire
