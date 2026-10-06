#pragma once

#ifndef MESH_HOLE_PUNCH_WIRE_H
#define MESH_HOLE_PUNCH_WIRE_H

#include "meshlink/peer_identity.h"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace invilite::Mesh {

    // NAT hole punching coordination (F7, docs/nat-traversal.md 4): 0xFF messages, one hop through a common neighbor R.
    //   PUNCH_REQUEST  A → R        target PeerId(32) + nonce(16)
    //   PUNCH_OFFER    R → B        initiator PeerId(32) + nonce(16) + endpoint of A as R sees it
    //   PUNCH_ACCEPT   B → R        nonce(16)
    //   PUNCH_DECLINE  B → R, R → A nonce(16) + reason(1)
    //   PUNCH_NOW      R → A and B  nonce(16) + endpoint of the other side as R sees it
    // endpoint = family(1: 4 or 6) + address(4 or 16) + port(2 BE). Endpoints are only ever observed by R (the remote
    // end of its connection with each side), never declared — nobody can point the other side at a third party.
    namespace HolePunchSubtype {
        constexpr uint16_t REQUEST = 0x0060;
        constexpr uint16_t OFFER   = 0x0061;
        constexpr uint16_t ACCEPT  = 0x0062;
        constexpr uint16_t DECLINE = 0x0063;
        constexpr uint16_t NOW     = 0x0064;
    }

    using HolePunchNonce = std::array<uint8_t, 16>;                                  // chosen by A, names one exchange

    // A public address and port as a NAT maps it — where the other side's SYN must go
    struct HolePunchEndpoint {
        std::string address;                                                        // numeric IPv4 / IPv6
        uint16_t    port = 0;
        bool operator==(const HolePunchEndpoint&) const = default;
    };

    // Why an exchange ends without PUNCH_NOW. The first four come from B (forwarded by R to A), the rest from R itself.
    enum class HolePunchDeclineReason : uint8_t {
        NoSlot           = 1,                                                       // B has no outbound slot for it
        AlreadyConnected = 2,                                                       // A and B are connected already
        Busy             = 3,                                                       // B is in another exchange with A
        TooManyAttempts  = 4,                                                       // B gives the pair a rest
        NotNeighbor      = 5,                                                       // R is not connected to B
        RateLimited      = 6,                                                       // A asked R too often
        PeerLeft         = 7,                                                       // the other side left R during the exchange
        NotAllowed       = 8,                                                       // protocol rule broken (e.g. the larger PeerId offered)
    };

    std::string_view holePunchDeclineReasonName(HolePunchDeclineReason reason);

    struct HolePunchRequest { PeerId target{};    HolePunchNonce nonce{}; };
    struct HolePunchOffer   { PeerId initiator{}; HolePunchNonce nonce{}; HolePunchEndpoint initiatorEndpoint; };
    struct HolePunchAccept  { HolePunchNonce nonce{}; };
    struct HolePunchDecline { HolePunchNonce nonce{}; HolePunchDeclineReason reason = HolePunchDeclineReason::NotAllowed; };
    struct HolePunchNow     { HolePunchNonce nonce{}; HolePunchEndpoint remoteEndpoint; };

    using HolePunchBody = std::variant<HolePunchRequest, HolePunchOffer, HolePunchAccept, HolePunchDecline, HolePunchNow>;

    // A coordination message and the neighbor it goes to (or came from) — what the state machines exchange with Network
    struct HolePunchMessage {
        PeerId          peer{};
        HolePunchBody   body;
    };

    namespace HolePunchCodec {
        struct Encoded {
            uint16_t             subtype = 0;
            std::vector<uint8_t> payload;                                           // without Group/Subtype
        };

        // Empty payload when an endpoint is not a numeric IP (never sent)
        Encoded encode(const HolePunchBody& body);

        // Exact length, known family and reason for the given subtype, otherwise nothing
        std::optional<HolePunchBody> decode(uint16_t subtype, std::span<const uint8_t> payload);

        [[nodiscard]] constexpr bool isHolePunchSubtype(uint16_t subtype) { return subtype >= HolePunchSubtype::REQUEST && subtype <= HolePunchSubtype::NOW; }
    }

} // namespace invilite::Mesh

#endif // MESH_HOLE_PUNCH_WIRE_H
