#ifndef MESH_ROUTER_TEST_MESH_H
#define MESH_ROUTER_TEST_MESH_H

// Fixtures shared by the Router tests and the Plumtree simulation: real Networks over loopback TCP in a declared
// topology, each with a Router and a recording listener.

#include "meshlink/router.h"
#include "network_test_node.h"

#include <algorithm>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace invilite::Mesh::TestHelpers {

using namespace std::chrono_literals;

struct DeliveryRecorder : RouterEventListener {
    void onMessageDelivered(const RoutedDelivery& delivery) override {
        std::lock_guard lock(this->mutex);
        this->deliveries.push_back(delivery);
    }

    size_t countOf(const PeerId& sender, uint64_t msgId) const {
        std::lock_guard lock(this->mutex);
        return static_cast<size_t>(std::count_if(this->deliveries.begin(), this->deliveries.end(), [&](const RoutedDelivery& d) { return d.sender == sender && d.msgId == msgId; }));
    }

    std::optional<RoutedDelivery> find(const PeerId& sender, uint64_t msgId) const {
        std::lock_guard lock(this->mutex);
        for (const auto& d : this->deliveries) if (d.sender == sender && d.msgId == msgId) return d;
        return std::nullopt;
    }

    size_t total() const {
        std::lock_guard lock(this->mutex);
        return this->deliveries.size();
    }

    void onAckReceived(const AckReceipt& receipt) override {
        std::lock_guard lock(this->mutex);
        this->acks.push_back(receipt);
    }

    std::vector<AckReceipt> acksFor(uint64_t msgId) const {
        std::lock_guard lock(this->mutex);
        std::vector<AckReceipt> matching;
        for (const auto& ack : this->acks) if (ack.acknowledgedMsgId == msgId) matching.push_back(ack);
        return matching;
    }

    void onRouteReported(const RouteReport& report) override {
        std::lock_guard lock(this->mutex);
        this->routeReports.push_back(report);
    }

    std::vector<RouteReport> reportsFor(uint64_t probeMsgId) const {
        std::lock_guard lock(this->mutex);
        std::vector<RouteReport> matching;
        for (const auto& report : this->routeReports) if (report.probeMsgId == probeMsgId) matching.push_back(report);
        return matching;
    }

    void onRouteFailed(const RouteFailure& failure) override {
        std::lock_guard lock(this->mutex);
        this->routeFailures.push_back(failure);
    }

    std::vector<RouteFailure> failuresFor(uint64_t msgId) const {
        std::lock_guard lock(this->mutex);
        std::vector<RouteFailure> matching;
        for (const auto& failure : this->routeFailures) if (failure.msgId == msgId) matching.push_back(failure);
        return matching;
    }

    void onStateReported(const StateReportReceipt& receipt) override {
        std::lock_guard lock(this->mutex);
        this->stateReports.push_back(receipt);
    }

    std::vector<StateReportReceipt> stateReportsFrom(const PeerId& node) const {
        std::lock_guard lock(this->mutex);
        std::vector<StateReportReceipt> matching;
        for (const auto& receipt : this->stateReports) if (receipt.from == node) matching.push_back(receipt);
        return matching;
    }

    mutable std::mutex           mutex;
    std::vector<StateReportReceipt> stateReports;
    std::vector<RoutedDelivery>  deliveries;
    std::vector<AckReceipt>      acks;
    std::vector<RouteReport>     routeReports;
    std::vector<RouteFailure>    routeFailures;
};

using Edge = std::pair<size_t, size_t>;

// Each node dials exactly its own edges (dialer, listener), so Topology adds no connections and the graph stays as
// declared.
struct RouterMesh {
    std::shared_ptr<std::array<uint8_t, 64>>        secret = makeSecret();
    std::vector<std::unique_ptr<TestNode>>          nodes;
    std::vector<std::unique_ptr<Router>>            routers;
    std::vector<std::shared_ptr<DeliveryRecorder>>  recorders;
    bool                                            ready = false;
    size_t                                          edgeCount = 0;

    RouterMesh(size_t count, const std::vector<Edge>& edges, const std::function<void(size_t, RouterConfig&)>& adjustRouter = {},
               const std::function<void(NetworkConfig&)>& adjustNetwork = {}) {
        this->edgeCount = edges.size();
        std::vector<uint16_t> outDegree(count, 0);
        std::vector<size_t>   degree(count, 0);
        for (const auto& [dialer, listener] : edges) { ++outDegree[dialer]; ++degree[dialer]; ++degree[listener]; }

        for (size_t i = 0; i < count; ++i) {
            this->nodes.push_back(std::make_unique<TestNode>(this->secret, "node" + std::to_string(i), [&](NetworkConfig& c) {
                // soft 0: Topology never dials (it would spend a slot on a gossiped node while the declared edges are still
                // being dialed). Hard leaves one slot over for a probe.
                c.connectionLimits.outbound = { .min = 0, .soft = 0, .hard = static_cast<uint16_t>(outDegree[i] + 1) };
                c.periodicPexMinInterval = 600s;
                c.periodicPexMaxInterval = 600s;
                if (adjustNetwork) adjustNetwork(c);
            }));
            this->nodes.back()->network->start();
        }

        // Last edges first: a node uses its outbound slots before gossip tells it about anyone else.
        for (auto it = edges.rbegin(); it != edges.rend(); ++it) {
            TestNode& dialer = *this->nodes[it->first];
            const size_t before = dialer.network->getConnectedPeerCount();
            dialer.network->connectToPeer("127.0.0.1", this->nodes[it->second]->port);
            if (!waitUntil([&] { return dialer.network->getConnectedPeerCount() > before; }, 5s)) return;
        }

        for (size_t i = 0; i < count; ++i) {
            RouterConfig config;
            // Presence, tree beacons and scheduled probes are off so tests count traffic exactly; tests of them turn them on.
            config.announcePresence = false;
            config.treeRoot.enabled = false;
            config.routeEvaluation.probing.enabled = false;
            if (adjustRouter) adjustRouter(i, config);
            this->routers.push_back(std::make_unique<Router>(*this->nodes[i]->network, this->nodes[i]->directory, this->nodes[i]->identity, config));
            this->recorders.push_back(std::make_shared<DeliveryRecorder>());
            this->routers.back()->addListener(this->recorders.back());
            this->routers.back()->start();
        }

        // Distant nodes' records are not required: gossip spreads a record only after someone dialed it successfully.
        this->ready = waitUntil([&] {
            for (size_t i = 0; i < count; ++i) if (this->routers[i]->getNeighbors().size() != degree[i]) return false;
            return true;
        }, 10s);
    }

    ~RouterMesh() {
        for (auto& router : this->routers) router->stop();
        for (auto& node : this->nodes) node->network->stop();
    }

    PeerId id(size_t i) const { return this->nodes[i]->identity->getPeerId(); }
    static PeerId peerIdOf(uint8_t fill) { PeerId id; id.fill(fill); return id; }

    bool allOthersDelivered(size_t sender, uint64_t msgId) const {
        for (size_t i = 0; i < this->nodes.size(); ++i) if (i != sender && this->recorders[i]->countOf(this->id(sender), msgId) == 0) return false;
        return true;
    }
};

inline std::vector<Edge> lineEdges(size_t count) {
    std::vector<Edge> edges;
    for (size_t i = 0; i + 1 < count; ++i) edges.push_back({ i, i + 1 });
    return edges;
}

} // namespace invilite::Mesh::TestHelpers

#endif // MESH_ROUTER_TEST_MESH_H
