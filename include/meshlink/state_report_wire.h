#ifndef MESH_STATE_REPORT_WIRE_H
#define MESH_STATE_REPORT_WIRE_H

#include "meshlink/peer_identity.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace invilite::Mesh {

    // Payloads of STATE_QUERY / STATE_REPORT (Group 0xFE / 0x0106-0x0107): "show me your state" for
    // diagnostics and `meshlink map`. Pure codec, no threads; the Router fills the report and carries it as a signed
    // routed message.
    //
    //   STATE_QUERY:  sections(2) | routeOffset(2) | routeCount(2)
    //   STATE_REPORT: queryMsgId(8) | formatVersion(1) | flags(1) | { sectionType(1) | length(4) | value }*
    //
    // All integers big-endian. Unknown section types and unknown counter ids are skipped / kept, so a newer node may report
    // more than an older collector understands.
    namespace StateReportWire {

        constexpr uint8_t   FORMAT_VERSION           = 1;
        constexpr size_t    DEFAULT_MAX_REPORT_BYTES = 256 * 1024;                  // well below Network's default 1 MB send queue

        // Section type on the wire = its bit in the query's section mask
        enum class StateSection : uint8_t {
            Node      = 0,                                                          // A: name, version, uptime, clock
            Neighbors = 1,                                                          // B: links, eager/lazy, traffic
            Plumtree  = 2,                                                          // C: tree counters
            Routes    = 3,                                                          // D: route table, one page
            Delivery  = 4,                                                          // E: what was sent, forwarded, delivered, lost
            Network   = 5,                                                          // F: connections, limits, address book, NAT
        };
        constexpr uint16_t sectionBit(StateSection section) { return static_cast<uint16_t>(1u << static_cast<uint8_t>(section)); }
        constexpr uint16_t ALL_SECTIONS = 0x003F;

        struct StateQuery {
            uint16_t    sections    = ALL_SECTIONS;
            uint16_t    routeOffset = 0;                                            // first destination of the route page (section D)
            uint16_t    routeCount  = 0xFFFF;                                       // destinations on the page; the report limit may cut it

            bool operator==(const StateQuery&) const = default;
        };

        // Stable wire ids of the counters in sections C, E and F, grouped by section. New counters get new ids; an id is
        // never reused for another meaning.
        enum class StateCounter : uint16_t {
            // C. Plumtree
            IhaveKeysSent           = 0x0100,
            IhaveKeysReceived       = 0x0101,
            GraftsSent              = 0x0102,
            GraftsReceived          = 0x0103,
            PrunesSent              = 0x0104,
            PrunesReceived          = 0x0105,
            DuplicatesDropped       = 0x0106,
            GraftsForMissing        = 0x0107,                                       // a message announced but never received: the tree failed
            TreeOptimizations       = 0x0108,
            BroadcastCacheEntries   = 0x0109,
            BroadcastCacheBytes     = 0x010A,
            MissingMessagesTracked  = 0x010B,
            EagerLinks              = 0x010C,
            LazyLinks               = 0x010D,
            // 0x010E: retired id, never reuse
            // E. Delivery
            FullMessagesSent        = 0x0200,
            Delivered               = 0x0201,
            UnicastForwarded        = 0x0202,
            RoutedForwarded         = 0x0203,
            LocalFloods             = 0x0204,
            AcksSent                = 0x0205,
            AcksReceived            = 0x0206,
            AwaitedReplies          = 0x0207,
            RouteErrorsSent         = 0x0208,
            RouteErrorsReceived     = 0x0209,
            ParkedForSenderRecord   = 0x020A,
            ParkedExpired           = 0x020B,
            UnknownModeReportsSent  = 0x020C,
            StateRepliesSent        = 0x020D,
            // F. Network
            ActiveInbound           = 0x0300,
            ActiveOutbound          = 0x0301,
            InboundSoftLimit        = 0x0302,
            InboundHardLimit        = 0x0303,
            OutboundSoftLimit       = 0x0304,
            OutboundHardLimit       = 0x0305,
            HandshakesInFlight      = 0x0306,
            NoSlotsRejectionsSent   = 0x0307,
            KnownPeers              = 0x0308,
            KnownAvailable          = 0x0309,
            KnownUnavailable        = 0x030A,
            KnownUnknown            = 0x030B,
            KnownProbing            = 0x030C,
            HolePunchBehindNat      = 0x030D,                                       // 1: peers see the node at a public address it does not announce
            HolePunchPrivateLinks   = 0x030E,                                       // active links to nodes nobody can dial
            HolePunchesRequested    = 0x030F,                                       // as A: PUNCH_REQUESTs sent
            HolePunchesDeclined     = 0x0310,                                       // as A: exchanges ended before NOW
            HolePunchesStarted      = 0x0311,                                       // NOW received, simultaneous connect began
            HolePunchesConnected    = 0x0312,
            HolePunchesFailed       = 0x0313,
            HolePunchesCoordinated  = 0x0314,                                       // as R: NOW sent to both sides
        };

        struct CounterValue {
            uint16_t    id    = 0;                                                  // a StateCounter, or one this build does not know
            uint64_t    value = 0;

            bool operator==(const CounterValue&) const = default;
        };
        using Counters = std::vector<CounterValue>;

        struct NodeState {
            std::string name;                                                       // at most 255 bytes on the wire
            uint8_t     protocolVersion       = 0;
            uint64_t    uptimeMs              = 0;                                  // counters are since the start: a restart resets them
            uint64_t    unixTimeMs            = 0;                                  // the node's clock when it wrote the report
            uint64_t    clockWindowRejections = 0;                                  // messages dropped for a timestamp outside +/-5 min
            std::optional<PeerId> treeRoot;                                         // whom it takes for the broadcast tree root (itself when it is)

            bool operator==(const NodeState&) const = default;
        };

        struct NeighborState {
            PeerId      peerId{};
            bool        inbound          = false;                                   // the neighbor dialed us
            bool        eager            = false;                                   // we send it full broadcasts (Plumtree); false = only IHAVE
            uint32_t    connectedSeconds = 0;
            uint64_t    bytesSent        = 0;
            uint64_t    bytesReceived    = 0;
            uint32_t    sendQueueBytes   = 0;
            bool        holePunched      = false;                                   // the link came from NAT hole punching; older nodes never set it

            bool operator==(const NeighborState&) const = default;
        };

        struct RouteState {
            PeerId                  destination{};
            PeerId                  via{};
            uint8_t                 hops             = 0;
            uint8_t                 evidence         = 0;                           // RouteTier as a raw value: 0 measured, 1 delivered, 2 hinted, 3 failing
            std::optional<uint32_t> rttMs;
            uint32_t                sinceConfirmedMs = 0;

            bool operator==(const RouteState&) const = default;
        };

        struct RoutesState {
            uint32_t                destinationCount = 0;                           // the whole table, not just this page
            uint16_t                offset           = 0;
            std::vector<RouteState> routes;                                         // every candidate of the page's destinations, best first

            bool operator==(const RoutesState&) const = default;
        };

        struct NetworkState {
            Counters                    counters;
            std::vector<std::string>    observedSelfAddresses;                      // how neighbors see us (OBSERVED_ADDRESS)

            bool operator==(const NetworkState&) const = default;
        };

        struct StateReport {
            uint64_t                                    queryMsgId    = 0;
            uint8_t                                     formatVersion = FORMAT_VERSION;
            bool                                        truncated     = false;      // a section did not fit the size limit and was left out
            std::optional<NodeState>                    node;
            std::optional<std::vector<NeighborState>>   neighbors;
            std::optional<Counters>                     plumtree;
            std::optional<RoutesState>                  routes;
            std::optional<Counters>                     delivery;
            std::optional<NetworkState>                 network;

            bool operator==(const StateReport&) const = default;
        };

        // Stable snake_case name of a counter for tools (JSON keys, tables); empty for an id this build does not know
        std::string_view     counterName(uint16_t id);

        std::vector<uint8_t> encodeQuery(const StateQuery& query);
        bool                 decodeQuery(std::span<const uint8_t> payload, StateQuery& out);   // exact length

        // Sections in order A..F; one that would take the report past maxBytes is left out and `truncated` set. Lists
        // longer than their wire count allows (65535 entries, 255 addresses) are cut to fit.
        std::vector<uint8_t> encodeReport(const StateReport& report, size_t maxBytes = DEFAULT_MAX_REPORT_BYTES);
        // Fails on a malformed known section; unknown section types are skipped. A repeated section type is malformed.
        bool                 decodeReport(std::span<const uint8_t> payload, StateReport& out);

    } // namespace StateReportWire

} // namespace invilite::Mesh

#endif // MESH_STATE_REPORT_WIRE_H
