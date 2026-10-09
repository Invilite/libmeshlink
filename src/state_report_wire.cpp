#include "meshlink/state_report_wire.h"
#include "wire_bytes.h"

#include <algorithm>
#include <limits>

namespace invilite::Mesh::StateReportWire {

using WireBytes::WireReader;
using WireBytes::writeBE16;
using WireBytes::writeBE32;
using WireBytes::writeBE64;
using WireBytes::writePeerId;

namespace {
    constexpr size_t   QUERY_SIZE          = 6;
    constexpr size_t   REPORT_HEADER_SIZE  = 10;                                    // queryMsgId + formatVersion + flags
    constexpr size_t   SECTION_HEADER_SIZE = 5;                                     // type + 4-byte length
    constexpr size_t   MAX_LIST_ENTRIES    = 0xFFFF;                                // 2-byte counts
    constexpr size_t   MAX_SHORT_ENTRIES   = 0xFF;                                  // 1-byte counts and string lengths
    constexpr uint8_t  FLAG_TRUNCATED      = 0x01;
    constexpr uint8_t  NEIGHBOR_INBOUND    = 0x01;
    constexpr uint8_t  NEIGHBOR_EAGER      = 0x02;
    constexpr uint8_t  NEIGHBOR_HOLE_PUNCHED = 0x04;
    constexpr uint32_t RTT_UNKNOWN         = 0xFFFFFFFF;

    void writeShortString(std::vector<uint8_t>& out, const std::string& text) {
        const size_t length = std::min(text.size(), MAX_SHORT_ENTRIES);
        out.push_back(static_cast<uint8_t>(length));
        out.insert(out.end(), text.begin(), text.begin() + static_cast<std::ptrdiff_t>(length));
    }

    bool readShortString(WireReader& reader, std::string& out) {
        uint8_t length;
        std::span<const uint8_t> bytes;
        if (!reader.readU8(length) || !reader.readBytes(length, bytes)) return false;
        out.assign(bytes.begin(), bytes.end());
        return true;
    }

    template <typename T>
    bool readBE(WireReader& reader, T& out) {
        uint64_t value;
        if (!reader.readUnsignedBE(sizeof(T), value)) return false;
        out = static_cast<T>(value);
        return true;
    }

    void writeCounters(std::vector<uint8_t>& out, const Counters& counters) {
        const size_t count = std::min(counters.size(), MAX_LIST_ENTRIES);
        writeBE16(out, static_cast<uint16_t>(count));
        for (size_t i = 0; i < count; ++i) {
            writeBE16(out, counters[i].id);
            writeBE64(out, counters[i].value);
        }
    }

    bool readCounters(WireReader& reader, Counters& out) {
        uint16_t count;
        if (!readBE(reader, count) || count > reader.remaining() / 10) return false;   // check before allocating
        out.resize(count);
        for (CounterValue& counter : out) {
            readBE(reader, counter.id);
            readBE(reader, counter.value);
        }
        return true;
    }

    std::vector<uint8_t> encodeNode(const NodeState& node) {
        std::vector<uint8_t> out;
        writeShortString(out, node.name);
        out.push_back(node.protocolVersion);
        writeBE64(out, node.uptimeMs);
        writeBE64(out, node.unixTimeMs);
        writeBE64(out, node.clockWindowRejections);
        out.push_back(node.treeRoot ? 1 : 0);
        if (node.treeRoot) writePeerId(out, *node.treeRoot);
        return out;
    }

    bool decodeNode(WireReader& reader, NodeState& out) {
        uint8_t hasRoot = 0;
        if (!readShortString(reader, out.name) || !reader.readU8(out.protocolVersion) || !readBE(reader, out.uptimeMs)
            || !readBE(reader, out.unixTimeMs) || !readBE(reader, out.clockWindowRejections) || !reader.readU8(hasRoot) || hasRoot > 1) return false;
        if (hasRoot) return reader.readPeerId(out.treeRoot.emplace());
        return true;
    }

    std::vector<uint8_t> encodeNeighbors(const std::vector<NeighborState>& neighbors) {
        std::vector<uint8_t> out;
        const size_t count = std::min(neighbors.size(), MAX_LIST_ENTRIES);
        writeBE16(out, static_cast<uint16_t>(count));
        for (size_t i = 0; i < count; ++i) {
            const NeighborState& neighbor = neighbors[i];
            writePeerId(out, neighbor.peerId);
            out.push_back(static_cast<uint8_t>((neighbor.inbound ? NEIGHBOR_INBOUND : 0) | (neighbor.eager ? NEIGHBOR_EAGER : 0) | (neighbor.holePunched ? NEIGHBOR_HOLE_PUNCHED : 0)));
            writeBE32(out, neighbor.connectedSeconds);
            writeBE64(out, neighbor.bytesSent);
            writeBE64(out, neighbor.bytesReceived);
            writeBE32(out, neighbor.sendQueueBytes);
        }
        return out;
    }

    bool decodeNeighbors(WireReader& reader, std::vector<NeighborState>& out) {
        constexpr size_t ENTRY_SIZE = WireBytes::PEER_ID_SIZE + 1 + 4 + 8 + 8 + 4;
        uint16_t count;
        if (!readBE(reader, count) || count > reader.remaining() / ENTRY_SIZE) return false;
        out.resize(count);
        for (NeighborState& neighbor : out) {
            uint8_t flags = 0;
            reader.readPeerId(neighbor.peerId);
            reader.readU8(flags);
            neighbor.inbound = (flags & NEIGHBOR_INBOUND) != 0;
            neighbor.eager   = (flags & NEIGHBOR_EAGER) != 0;
            neighbor.holePunched = (flags & NEIGHBOR_HOLE_PUNCHED) != 0;
            readBE(reader, neighbor.connectedSeconds);
            readBE(reader, neighbor.bytesSent);
            readBE(reader, neighbor.bytesReceived);
            readBE(reader, neighbor.sendQueueBytes);
        }
        return true;
    }

    std::vector<uint8_t> encodeRoutes(const RoutesState& routes) {
        std::vector<uint8_t> out;
        writeBE32(out, routes.destinationCount);
        writeBE16(out, routes.offset);
        const size_t count = std::min(routes.routes.size(), MAX_LIST_ENTRIES);
        writeBE16(out, static_cast<uint16_t>(count));
        for (size_t i = 0; i < count; ++i) {
            const RouteState& route = routes.routes[i];
            writePeerId(out, route.destination);
            writePeerId(out, route.via);
            out.push_back(route.hops);
            out.push_back(route.evidence);
            writeBE32(out, route.rttMs ? std::min(*route.rttMs, RTT_UNKNOWN - 1) : RTT_UNKNOWN);
            writeBE32(out, route.sinceConfirmedMs);
        }
        return out;
    }

    bool decodeRoutes(WireReader& reader, RoutesState& out) {
        constexpr size_t ENTRY_SIZE = 2 * WireBytes::PEER_ID_SIZE + 1 + 1 + 4 + 4;
        uint16_t count;
        if (!readBE(reader, out.destinationCount) || !readBE(reader, out.offset) || !readBE(reader, count)) return false;
        if (count > reader.remaining() / ENTRY_SIZE) return false;
        out.routes.resize(count);
        for (RouteState& route : out.routes) {
            uint32_t rtt = 0;
            reader.readPeerId(route.destination);
            reader.readPeerId(route.via);
            reader.readU8(route.hops);
            reader.readU8(route.evidence);
            readBE(reader, rtt);
            route.rttMs = rtt == RTT_UNKNOWN ? std::nullopt : std::optional(rtt);
            readBE(reader, route.sinceConfirmedMs);
        }
        return true;
    }

    std::vector<uint8_t> encodeNetwork(const NetworkState& network) {
        std::vector<uint8_t> out;
        writeCounters(out, network.counters);
        const size_t count = std::min(network.observedSelfAddresses.size(), MAX_SHORT_ENTRIES);
        out.push_back(static_cast<uint8_t>(count));
        for (size_t i = 0; i < count; ++i) writeShortString(out, network.observedSelfAddresses[i]);
        return out;
    }

    bool decodeNetwork(WireReader& reader, NetworkState& out) {
        uint8_t count;
        if (!readCounters(reader, out.counters) || !reader.readU8(count)) return false;
        out.observedSelfAddresses.resize(count);
        for (std::string& address : out.observedSelfAddresses) if (!readShortString(reader, address)) return false;
        return true;
    }

    // One known section's value; the decoder must consume all of it
    bool decodeSection(StateSection section, std::span<const uint8_t> value, StateReport& out) {
        WireReader reader(value);
        bool parsed = false;
        switch (section) {
            case StateSection::Node:      parsed = decodeNode(reader, out.node.emplace()); break;
            case StateSection::Neighbors: parsed = decodeNeighbors(reader, out.neighbors.emplace()); break;
            case StateSection::Plumtree:  parsed = readCounters(reader, out.plumtree.emplace()); break;
            case StateSection::Routes:    parsed = decodeRoutes(reader, out.routes.emplace()); break;
            case StateSection::Delivery:  parsed = readCounters(reader, out.delivery.emplace()); break;
            case StateSection::Network:   parsed = decodeNetwork(reader, out.network.emplace()); break;
        }
        return parsed && reader.remaining() == 0;
    }

    bool isKnownSection(uint8_t type) { return type <= static_cast<uint8_t>(StateSection::Network); }
} // namespace

std::string_view counterName(uint16_t id) {
    switch (static_cast<StateCounter>(id)) {
        case StateCounter::IhaveKeysSent: return "ihave_keys_sent";
        case StateCounter::IhaveKeysReceived: return "ihave_keys_received";
        case StateCounter::GraftsSent: return "grafts_sent";
        case StateCounter::GraftsReceived: return "grafts_received";
        case StateCounter::PrunesSent: return "prunes_sent";
        case StateCounter::PrunesReceived: return "prunes_received";
        case StateCounter::DuplicatesDropped: return "duplicates_dropped";
        case StateCounter::GraftsForMissing: return "grafts_for_missing";
        case StateCounter::TreeOptimizations: return "tree_optimizations";
        case StateCounter::BroadcastCacheEntries: return "broadcast_cache_entries";
        case StateCounter::BroadcastCacheBytes: return "broadcast_cache_bytes";
        case StateCounter::MissingMessagesTracked: return "missing_messages_tracked";
        case StateCounter::EagerLinks: return "eager_links";
        case StateCounter::LazyLinks: return "lazy_links";
        case StateCounter::FullMessagesSent: return "full_messages_sent";
        case StateCounter::Delivered: return "delivered";
        case StateCounter::UnicastForwarded: return "unicast_forwarded";
        case StateCounter::RoutedForwarded: return "routed_forwarded";
        case StateCounter::LocalFloods: return "local_floods";
        case StateCounter::AcksSent: return "acks_sent";
        case StateCounter::AcksReceived: return "acks_received";
        case StateCounter::AwaitedReplies: return "awaited_replies";
        case StateCounter::RouteErrorsSent: return "route_errors_sent";
        case StateCounter::RouteErrorsReceived: return "route_errors_received";
        case StateCounter::ParkedForSenderRecord: return "parked_for_sender_record";
        case StateCounter::ParkedExpired: return "parked_expired";
        case StateCounter::UnknownModeReportsSent: return "unknown_mode_reports_sent";
        case StateCounter::StateRepliesSent: return "state_replies_sent";
        case StateCounter::ActiveInbound: return "active_inbound";
        case StateCounter::ActiveOutbound: return "active_outbound";
        case StateCounter::InboundSoftLimit: return "inbound_soft_limit";
        case StateCounter::InboundHardLimit: return "inbound_hard_limit";
        case StateCounter::OutboundSoftLimit: return "outbound_soft_limit";
        case StateCounter::OutboundHardLimit: return "outbound_hard_limit";
        case StateCounter::HandshakesInFlight: return "handshakes_in_flight";
        case StateCounter::NoSlotsRejectionsSent: return "no_slots_rejections_sent";
        case StateCounter::KnownPeers: return "known_peers";
        case StateCounter::KnownAvailable: return "known_available";
        case StateCounter::KnownUnavailable: return "known_unavailable";
        case StateCounter::KnownUnknown: return "known_unknown";
        case StateCounter::KnownProbing: return "known_probing";
        case StateCounter::HolePunchBehindNat: return "hole_punch_behind_nat";
        case StateCounter::HolePunchPrivateLinks: return "hole_punch_private_links";
        case StateCounter::HolePunchesRequested: return "hole_punches_requested";
        case StateCounter::HolePunchesDeclined: return "hole_punches_declined";
        case StateCounter::HolePunchesStarted: return "hole_punches_started";
        case StateCounter::HolePunchesConnected: return "hole_punches_connected";
        case StateCounter::HolePunchesFailed: return "hole_punches_failed";
        case StateCounter::HolePunchesCoordinated: return "hole_punches_coordinated";
    }
    return {};
}

std::vector<uint8_t> encodeQuery(const StateQuery& query) {
    std::vector<uint8_t> out;
    out.reserve(QUERY_SIZE);
    writeBE16(out, query.sections);
    writeBE16(out, query.routeOffset);
    writeBE16(out, query.routeCount);
    return out;
}

bool decodeQuery(std::span<const uint8_t> payload, StateQuery& out) {
    if (payload.size() != QUERY_SIZE) return false;
    WireReader reader(payload);
    return readBE(reader, out.sections) && readBE(reader, out.routeOffset) && readBE(reader, out.routeCount);
}

std::vector<uint8_t> encodeReport(const StateReport& report, size_t maxBytes) {
    std::vector<std::pair<StateSection, std::vector<uint8_t>>> sections;
    if (report.node)      sections.emplace_back(StateSection::Node, encodeNode(*report.node));
    if (report.neighbors) sections.emplace_back(StateSection::Neighbors, encodeNeighbors(*report.neighbors));
    if (report.plumtree)  { std::vector<uint8_t> value; writeCounters(value, *report.plumtree); sections.emplace_back(StateSection::Plumtree, std::move(value)); }
    if (report.routes)    sections.emplace_back(StateSection::Routes, encodeRoutes(*report.routes));
    if (report.delivery)  { std::vector<uint8_t> value; writeCounters(value, *report.delivery); sections.emplace_back(StateSection::Delivery, std::move(value)); }
    if (report.network)   sections.emplace_back(StateSection::Network, encodeNetwork(*report.network));

    std::vector<uint8_t> body;
    bool truncated = report.truncated;
    for (const auto& [section, value] : sections) {
        if (REPORT_HEADER_SIZE + body.size() + SECTION_HEADER_SIZE + value.size() > maxBytes || value.size() > std::numeric_limits<uint32_t>::max()) {
            truncated = true;                                                       // left out; later, smaller sections may still fit
            continue;
        }
        body.push_back(static_cast<uint8_t>(section));
        writeBE32(body, static_cast<uint32_t>(value.size()));
        body.insert(body.end(), value.begin(), value.end());
    }

    std::vector<uint8_t> out;
    out.reserve(REPORT_HEADER_SIZE + body.size());
    writeBE64(out, report.queryMsgId);
    out.push_back(report.formatVersion);
    out.push_back(truncated ? FLAG_TRUNCATED : 0);
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

bool decodeReport(std::span<const uint8_t> payload, StateReport& out) {
    out = StateReport{};
    WireReader reader(payload);
    uint8_t flags;
    if (!readBE(reader, out.queryMsgId) || !reader.readU8(out.formatVersion) || !reader.readU8(flags)) return false;
    out.truncated = (flags & FLAG_TRUNCATED) != 0;

    uint16_t seen = 0;
    while (reader.remaining() > 0) {
        uint8_t type;
        uint32_t length;
        std::span<const uint8_t> value;
        if (!reader.readU8(type) || !readBE(reader, length) || !reader.readBytes(length, value)) return false;
        if (!isKnownSection(type)) continue;                                        // a newer node's section
        const uint16_t bit = sectionBit(static_cast<StateSection>(type));
        if ((seen & bit) != 0 || !decodeSection(static_cast<StateSection>(type), value, out)) return false;
        seen |= bit;
    }
    return true;
}

} // namespace invilite::Mesh::StateReportWire
