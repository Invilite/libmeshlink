#pragma once

#ifndef MESH_ROUTER_WIRE_H
#define MESH_ROUTER_WIRE_H

#include "meshlink/peer_identity.h"
#include "meshlink/routed_message_key.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace invilite::Mesh {

    // Routed message format (layer 2b, docs/router.md section 3.4) — pure data + codec, no threads, no peer knowledge.
    //
    //   Group(1) | Subtype(2)                                     — layer 1 (Network): Group 0x00..0xFD, or 0xFE with subtype 0x0100..0x01FF
    //   version+mode(1) | flags(1) | ttlRemaining(1) | ttlInitial(1) | msgId(8) | sentAt(4) | sender(32)   — fixed 48 B
    //   [destination(32)]                                          mode ROUTED / UNICAST
    //   [count(1) + nextHopIndex(1) + count × PeerId(32)]          mode ROUTED
    //   [totalLength(2) + TLV...]                                  flag HAS_EXTENSIONS, TLV = type(1) | length(2) | value
    //   [signature(64)]                                            mode FLOOD / BROADCAST, every routed Router message (Group 0xFE)
    //   payload                                                    up to the end of the frame
    //
    // All multi-byte integers big-endian. Fields mutated by relays (ttlRemaining, nextHopIndex, per-hop extensions,
    // HAS_EXTENSIONS bit) are outside the signature; everything else is signed.

    // How a message travels (docs/router.md 4.0). FLOOD and BROADCAST go to every node, have no destination and are always
    // signed; they differ only in how copies spread. A mode this node does not know is ignored and reported to the neighbor.
    enum class RoutingMode : uint8_t {
        Flood     = 0x0,                                                            // to every node: full copy to every neighbor
        Broadcast = 0x1,                                                            // to every node: Plumtree — tree built from traffic, other links get announcements
        Routed    = 0x2,                                                            // to one node along the hops the sender lists
        Unicast   = 0x3,                                                            // to one node; each hop picks the next hop, floods locally without a route
    };

    enum class RouteErrorReason : uint8_t {
        NextHopNotNeighbor = 0x01,                                                  // next source-route hop is not my neighbor
        NextHopSendRefused = 0x02,                                                  // send to the next hop refused (queue full / connection closed)
    };

    // TLV extension. Type bit 7 = critical (unknown → reject message), bit 6 = per-hop (unsigned, relays may change it).
    struct RoutingExtension {
        uint8_t                 type = 0;
        std::vector<uint8_t>    value;

        bool isCritical() const { return (type & 0x80) != 0; }
        bool isPerHop()   const { return (type & 0x40) != 0; }

        bool operator==(const RoutingExtension&) const = default;
    };

    struct SourceRoute {
        uint8_t                 nextHopIndex = 0;                                   // [M] index into hops; == hops.size() means the route is used up
        std::vector<PeerId>     hops;                                               // [S] at most 255

        bool operator==(const SourceRoute&) const = default;
    };

    // Decoded routed message. Optional parts are present exactly when the mode / flags require them (encode enforces it).
    struct RoutedMessage {
        uint8_t                         group   = 0;                                // 0x00..0xFD application, 0xFE Router's own routed message; signed — a relay cannot move it elsewhere
        uint16_t                        subtype = 0;                                // application subtype (untouched by the Router), or a routed Router message type
        RoutingMode                     mode    = RoutingMode::Broadcast;
        bool                            ackRequested = false;                       // every addressee that receives it answers with an ACK
        uint8_t                         reservedFlagBits = 0;                       // flag bits 7..2 as received; kept so a re-encoded message still matches the sender's signature
        uint8_t                         ttlRemaining = 0;                           // [M]
        uint8_t                         ttlInitial   = 0;
        uint64_t                        msgId = 0;                                  // random; duplicate / replay key = (sender, msgId)
        uint32_t                        sentAtUnixSeconds = 0;
        PeerId                          sender{};
        std::optional<PeerId>           destination;                                // mode Routed / Unicast
        std::optional<SourceRoute>      sourceRoute;                                // mode Routed
        std::vector<RoutingExtension>   extensions;                                 // all received extensions, known or not — unknown signed ones must survive forwarding
        std::vector<uint8_t>            signature;                                  // 64 B when requiresSignature(group, mode), empty otherwise
        std::vector<uint8_t>            payload;

        bool operator==(const RoutedMessage&) const = default;
    };

    // ACK payload (Group 0xFE / ACK): sent by every addressee that received a message with ACK_REQUESTED — the destination
    // of ROUTED / UNICAST, every node for FLOOD / BROADCAST. Relays never acknowledge.
    struct AckPayload {
        uint64_t                acknowledgedMsgId = 0;

        bool operator==(const AckPayload&) const = default;
    };

    // ROUTE_ERROR payload. Message sender = reporting node, destination = sender of the stuck message.
    struct RouteErrorPayload {
        uint64_t                stuckMsgId = 0;
        PeerId                  unreachableDestination{};
        RouteErrorReason        reason = RouteErrorReason::NextHopNotNeighbor;      // unknown values are kept, not rejected

        bool operator==(const RouteErrorPayload&) const = default;
    };

    // UNKNOWN_DELIVERY_MODE payload: "I do not know the mode of this message and did not forward it" (neighbor-only)
    struct UnknownDeliveryModeReport {
        uint8_t                 mode = 0;                                           // the raw mode nibble we could not handle
        RoutedMessageKey        message;

        bool operator==(const UnknownDeliveryModeReport&) const = default;
    };

    // Receive-side validation outcome (docs/router.md 3.6). Signature is checked separately (verifySignature) because
    // the sender's key comes from PeerDirectory, which the codec does not know.
    enum class RoutedMessageStatus : int {
        Success                    =   0,
        MalformedEncoding          =  -1,                                           // truncated, length fields beyond the frame, bad TLV framing, malformed ACK / ROUTE_ERROR payload
        NotRoutedGroup             =  -2,                                           // Group 0xFF and neighbor-only Group 0xFE subtypes carry no routing header
        UnsupportedVersion         =  -3,
        UnknownMode                =  -4,                                           // fixed header (sender, msgId, mode) is filled in: the neighbor gets UNKNOWN_DELIVERY_MODE
        RouterMessageToEveryNode   =  -5,                                           // routed Router message (Group 0xFE) in FLOOD / BROADCAST
        InvalidTtl                 =  -6,                                           // ttlInitial == 0 or ttlRemaining > ttlInitial
        SourceRouteIndexOutOfRange =  -7,
        TimestampOutOfWindow       =  -8,
        UnknownCriticalExtension   =  -9,
    };

    namespace RouterWire {

        constexpr uint8_t  WIRE_VERSION          = 1;
        constexpr uint8_t  ROUTER_PROTOCOL_GROUP = 0xFE;                            // Router's own messages (section 3.3)
        constexpr uint8_t  MAX_ROUTED_GROUP      = 0xFD;
        constexpr size_t   FIXED_HEADER_SIZE     = 48;
        constexpr size_t   SIGNATURE_SIZE        = 64;
        constexpr uint8_t  EXTENSION_SENT_TO     = 0x40;                            // per-hop Bloom filter of neighbors sent the full message (R-7)

        // Group 0xFE subtypes 0x0001..0x00FF: neighbor-only control, no routing header
        constexpr uint16_t SUBTYPE_NEIGHBORS             = 0x0001;
        constexpr uint16_t SUBTYPE_IHAVE                 = 0x0002;
        constexpr uint16_t SUBTYPE_GRAFT                 = 0x0003;
        constexpr uint16_t SUBTYPE_PRUNE                 = 0x0004;
        constexpr uint16_t SUBTYPE_UNKNOWN_DELIVERY_MODE = 0x0005;
        // Group 0xFE subtypes 0x0100..0x01FF: the Router's own routed messages — routing header, always signed, ROUTED / UNICAST only
        constexpr uint16_t FIRST_ROUTED_ROUTER_SUBTYPE   = 0x0100;
        constexpr uint16_t LAST_ROUTED_ROUTER_SUBTYPE    = 0x01FF;
        constexpr uint16_t SUBTYPE_ACK                   = 0x0100;
        constexpr uint16_t SUBTYPE_ROUTE_ERROR           = 0x0101;
        constexpr uint16_t SUBTYPE_RECORD_ROUTE          = 0x0102;                  // route probe (R-5)
        constexpr uint16_t SUBTYPE_ROUTE_REPORT          = 0x0103;                  // probe answer from the destination (R-5)

        // FLOOD and BROADCAST: to every node, no destination
        bool reachesEveryNode(RoutingMode mode);

        // Whether a Network frame with this Group / Subtype starts with a routing header
        bool carriesRoutingHeader(uint8_t group, uint16_t subtype);

        // Ed25519 signature present: FLOOD and BROADCAST (D8), and every routed Router message (D5). Application
        // ROUTED / UNICAST data relies on E2E (D12).
        bool requiresSignature(uint8_t group, RoutingMode mode);

        // Full Network frame: Group | Subtype | routing header | payload — ready for Network::sendToPeer.
        // Returns an empty vector when the message is inconsistent (optional parts not matching mode / flags,
        // signature presence not matching requiresSignature, counts or lengths over their field size, invalid TTL,
        // Group / Subtype without a routing header, unknown mode, Router message in FLOOD / BROADCAST, source-route index past the route).
        std::vector<uint8_t> encode(const RoutedMessage& message);

        // Decode and validate a received message. Network has already split off Group and Subtype, so they come
        // separately and `body` starts at the routing header. sentAt must lie within now ± maxClockSkew.
        // On failure `out` is unspecified — do not use it — except UnknownMode, where the fixed header is filled in.
        RoutedMessageStatus decode(uint8_t group, uint16_t subtype, std::span<const uint8_t> body, std::chrono::system_clock::time_point now,
                                   RoutedMessage& out, std::chrono::seconds maxClockSkew = std::chrono::minutes(5));

        // Bytes covered by the sender's Ed25519 signature:
        //   "MeshLink-Router-V1" | Group | Subtype | version+mode | flags without HAS_EXTENSIONS | ttlInitial | msgId | sentAt
        //   | sender | [destination] | [count + source-route hops] | signedExtensionsLength(2) | signed TLVs | payload
        // The signed-extensions length keeps the TLV / payload boundary inside the signature: without it a relay could drop
        // a signed extension and prepend its bytes to the payload without breaking the signature.
        std::vector<uint8_t> bytesToSign(const RoutedMessage& message);

        // Ed25519 check against the sender's public key (from its SignedPeerRecord). False when the signature is absent.
        bool verifySignature(const RoutedMessage& message, std::span<const uint8_t> senderEd25519Pub);

        // Payloads of the routed Router messages. Decoders require the exact length (no trailing bytes).
        std::vector<uint8_t> encodeAckPayload(const AckPayload& ack);
        bool                 decodeAckPayload(std::span<const uint8_t> payload, AckPayload& out);
        std::vector<uint8_t> encodeRouteErrorPayload(const RouteErrorPayload& error);
        bool                 decodeRouteErrorPayload(std::span<const uint8_t> payload, RouteErrorPayload& out);

        // Neighbor-only control (Group 0xFE, subtypes 0x0001..0x00FF, section 3.3). Encoders return the whole Network frame
        // (Group | Subtype | payload) ready for Network::sendToPeer, or an empty vector when the content does not fit;
        // decoders take the payload Network split off and require the exact length.
        constexpr size_t MAX_KEYS_PER_CONTROL_MESSAGE = 255;                        // 1-byte count

        // IHAVE announces 1..255 messages; an empty IHAVE means nothing and is refused both ways
        std::vector<uint8_t> encodeIhave(std::span<const RoutedMessageKey> keys);
        bool                 decodeIhave(std::span<const uint8_t> payload, std::vector<RoutedMessageKey>& out);
        // GRAFT asks for 0..255 messages and makes the sender of the GRAFT eager; 0 = only "send me full copies from now on"
        std::vector<uint8_t> encodeGraft(std::span<const RoutedMessageKey> keys);
        bool                 decodeGraft(std::span<const uint8_t> payload, std::vector<RoutedMessageKey>& out);
        std::vector<uint8_t> encodePrune();
        bool                 decodePrune(std::span<const uint8_t> payload);
        std::vector<uint8_t> encodeUnknownDeliveryMode(const UnknownDeliveryModeReport& report);
        bool                 decodeUnknownDeliveryMode(std::span<const uint8_t> payload, UnknownDeliveryModeReport& out);

    } // namespace RouterWire

} // namespace invilite::Mesh

#endif // MESH_ROUTER_WIRE_H
