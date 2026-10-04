#pragma once

#ifndef MESH_ROUTER_WIRE_H
#define MESH_ROUTER_WIRE_H

#include "meshlink/peer_identity.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace invilite::Mesh {

    // Routed message format (layer 2b, docs/router.md section 3.4) — pure data + codec, no threads, no peer knowledge.
    //
    //   Group(1) | Subtype(2)                                     — layer 1 (Network), Group 0x00..0xFD
    //   version+mode(1) | flags(1) | ttlRemaining(1) | ttlInitial(1) | msgId(8) | sentAt(4) | sender(32)   — fixed 48 B
    //   [destination(32)]                                          mode != BROADCAST
    //   [count(1) + nextHopIndex(1) + count × PeerId(32)]          mode == SOURCE_ROUTED
    //   [count(1) + count × PeerId(32)]                            flag RECORD_ROUTE
    //   [totalLength(2) + TLV...]                                  flag HAS_EXTENSIONS, TLV = type(1) | length(2) | value
    //   [signature(64)]                                            mode BROADCAST, kind ACK, kind ROUTE_ERROR
    //   payload                                                    up to the end of the frame
    //
    // All multi-byte integers big-endian. Fields mutated by relays (ttlRemaining, nextHopIndex, recordedRoute,
    // per-hop extensions, HAS_EXTENSIONS bit) are outside the signature; everything else is signed.

    enum class RoutingMode : uint8_t {
        Broadcast    = 0x0,                                                         // to every node, signed sender
        Unicast      = 0x1,                                                         // each hop picks the next hop from local knowledge
        SourceRouted = 0x2,                                                         // sender lists the hops
        Flood        = 0x3,                                                         // to the destination by flooding, bounded by TTL
    };

    enum class RoutedMessageKind : uint8_t {
        Data       = 0b00,
        Ack        = 0b01,
        RouteError = 0b10,
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
        uint8_t                         group   = 0;                                // 0x00..0xFD, signed — a relay cannot move the message to another application
        uint16_t                        subtype = 0;                                // application subtype, untouched by the Router
        RoutingMode                     mode    = RoutingMode::Broadcast;
        RoutedMessageKind               kind    = RoutedMessageKind::Data;
        bool                            ackRequested = false;
        uint8_t                         reservedFlagBits = 0;                       // flag bits 7..5 as received; kept so a re-encoded message still matches the sender's signature
        uint8_t                         ttlRemaining = 0;                           // [M]
        uint8_t                         ttlInitial   = 0;
        uint64_t                        msgId = 0;                                  // random; duplicate / replay key = (sender, msgId)
        uint32_t                        sentAtUnixSeconds = 0;
        PeerId                          sender{};
        std::optional<PeerId>           destination;                                // mode != Broadcast
        std::optional<SourceRoute>      sourceRoute;                                // mode == SourceRouted
        std::optional<std::vector<PeerId>> recordedRoute;                           // [M] RECORD_ROUTE flag; each hop appends itself
        std::vector<RoutingExtension>   extensions;                                 // all received extensions, known or not — unknown signed ones must survive forwarding
        std::vector<uint8_t>            signature;                                  // 64 B when requiresSignature(mode, kind), empty otherwise
        std::vector<uint8_t>            payload;

        bool operator==(const RoutedMessage&) const = default;
    };

    // ACK payload: the destination signs the route the acknowledged message took to reach it.
    struct AckPayload {
        uint64_t                acknowledgedMsgId = 0;
        std::vector<PeerId>     receivedRoute;                                      // empty when the acknowledged message had no RECORD_ROUTE

        bool operator==(const AckPayload&) const = default;
    };

    // ROUTE_ERROR payload. Message sender = reporting node, destination = sender of the stuck message.
    struct RouteErrorPayload {
        uint64_t                stuckMsgId = 0;
        PeerId                  unreachableDestination{};
        RouteErrorReason        reason = RouteErrorReason::NextHopNotNeighbor;      // unknown values are kept, not rejected

        bool operator==(const RouteErrorPayload&) const = default;
    };

    // Receive-side validation outcome (docs/router.md 3.6). Signature is checked separately (verifySignature) because
    // the sender's key comes from PeerDirectory, which the codec does not know.
    enum class RoutedMessageStatus : int {
        Success                    =   0,
        MalformedEncoding          =  -1,                                           // truncated, length fields beyond the frame, bad TLV framing, malformed ACK / ROUTE_ERROR payload
        NotRoutedGroup             =  -2,                                           // Group 0xFE / 0xFF carry no routing header
        UnsupportedVersion         =  -3,
        ReservedMode               =  -4,
        ReservedKind               =  -5,
        KindNotAllowedInMode       =  -6,                                           // ACK / ROUTE_ERROR in BROADCAST
        InvalidTtl                 =  -7,                                           // ttlInitial == 0 or ttlRemaining > ttlInitial
        SourceRouteIndexOutOfRange =  -8,
        TimestampOutOfWindow       =  -9,
        UnknownCriticalExtension   = -10,
    };

    namespace RouterWire {

        constexpr uint8_t  WIRE_VERSION          = 1;
        constexpr uint8_t  ROUTER_PROTOCOL_GROUP = 0xFE;                            // Router control, neighbor-only (section 3.3)
        constexpr uint8_t  MAX_ROUTED_GROUP      = 0xFD;
        constexpr size_t   FIXED_HEADER_SIZE     = 48;
        constexpr size_t   SIGNATURE_SIZE        = 64;
        constexpr uint8_t  EXTENSION_SENT_TO     = 0x40;                            // per-hop Bloom filter of neighbors sent the full message (R-7)

        // Ed25519 signature present: every BROADCAST, every ACK and ROUTE_ERROR. UNICAST DATA relies on E2E (D12).
        bool requiresSignature(RoutingMode mode, RoutedMessageKind kind);

        // Full Network frame: Group | Subtype | routing header | payload — ready for Network::sendToPeer.
        // Returns an empty vector when the message is inconsistent (optional parts not matching mode / flags,
        // signature presence not matching requiresSignature, counts or lengths over their field size, invalid TTL,
        // group outside 0x00..0xFD, reserved mode / kind values, source-route index past the route).
        std::vector<uint8_t> encode(const RoutedMessage& message);

        // Decode and validate a received message. Network has already split off Group and Subtype, so they come
        // separately and `body` starts at the routing header. sentAt must lie within now ± maxClockSkew.
        // On failure `out` is unspecified — do not use it.
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

        // Kind-specific payloads. Decoders require the exact length (no trailing bytes); encoders return an empty vector
        // when the route does not fit the 1-byte count.
        std::vector<uint8_t> encodeAckPayload(const AckPayload& ack);
        bool                 decodeAckPayload(std::span<const uint8_t> payload, AckPayload& out);
        std::vector<uint8_t> encodeRouteErrorPayload(const RouteErrorPayload& error);
        bool                 decodeRouteErrorPayload(std::span<const uint8_t> payload, RouteErrorPayload& out);

    } // namespace RouterWire

} // namespace invilite::Mesh

#endif // MESH_ROUTER_WIRE_H
