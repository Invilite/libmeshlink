#include "meshlink/router.h"
#include "meshlink/network.h"
#include "meshlink/router_wire.h"
#include "meshlink/thread_safe_queue.h"
#include "meshlink/thread_signals.h"
#include "transport/platform.h"

#include <chrono>
#include <cstdio>
#include <iostream>

namespace invilite::Mesh {

namespace {
    constexpr std::chrono::milliseconds EVENT_WAIT{100};                            // bounds how long stop() waits for the loop to notice

    std::string shortPeerId(const PeerId& id) {
        char buf[13];
        std::snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x%02x", id[0], id[1], id[2], id[3], id[4], id[5]);
        return buf;
    }
}

struct Router::Event {
    enum class Type { NeighborConnected, NeighborDisconnected, MessageReceived };

    Type            type = Type::MessageReceived;
    PeerId          peerId{};                                                       // neighbor events
    NetworkMessage  message;                                                        // MessageReceived
};

// The only object Network holds: it owns the queue, so Network may outlive the Router without dangling.
// Every callback copies the event into the queue and returns — no routing work on Network's threads.
class Router::EventInbox : public NetworkEventListener {
public:
    void onPeerConnected(const PeerIdentity& identity) override { this->events.push({ Event::Type::NeighborConnected, identity.getPeerId(), {} }); }
    void onPeerDisconnected(const PeerId& peerId) override      { this->events.push({ Event::Type::NeighborDisconnected, peerId, {} }); }
    void onMessageReceived(const NetworkMessage& message) override { this->events.push({ Event::Type::MessageReceived, message.source, message }); }

    ThreadSafeQueue<Event> events;
};

Router::Router(Network& network) : network(network) {}

Router::~Router() {
    this->stop();
}

void Router::start() {
    if (this->running.exchange(true)) return;

    // A fresh inbox per run: nothing left over from a previous run is replayed
    this->inbox = std::make_shared<EventInbox>();
    this->network.addListener(this->inbox);

    // Seed after registering, before the loop drains anything. A peer that connects or leaves around this point shows up
    // in the queue as well, and queued events are applied after the seed — so the final view is right either way.
    {
        std::lock_guard lock(this->neighborsMutex);
        this->neighbors.clear();
        for (const PeerId& peerId : this->network.getConnectedPeers()) this->neighbors.insert(peerId);
    }

    this->routerThread = std::thread(&Router::routerLoop, this);
    Transport::Platform::setThreadName(this->routerThread, "Router");
}

void Router::stop() {
    if (!this->running.exchange(false)) return;

    this->network.removeListener(this->inbox);
    this->inbox->events.shutdown();
    if (this->routerThread.joinable()) this->routerThread.join();

    std::lock_guard lock(this->neighborsMutex);
    this->neighbors.clear();
}

std::vector<PeerId> Router::getNeighbors() const {
    std::lock_guard lock(this->neighborsMutex);
    return { this->neighbors.begin(), this->neighbors.end() };
}

void Router::routerLoop() {
    blockSigpipeInCurrentThread();

    while (this->running.load()) {
        auto event = this->inbox->events.waitPop(EVENT_WAIT);
        if (event) this->processEvent(*event);
    }
}

void Router::processEvent(Event& event) {
    switch (event.type) {
        case Event::Type::NeighborConnected: {
            std::lock_guard lock(this->neighborsMutex);
            this->neighbors.insert(event.peerId);
            break;
        }
        case Event::Type::NeighborDisconnected: {
            std::lock_guard lock(this->neighborsMutex);
            this->neighbors.erase(event.peerId);
            break;
        }
        case Event::Type::MessageReceived:
            // Until the Dispatch thread goes (C6), messages travel a different thread than disconnects: a message from a
            // neighbor may arrive after its disconnect event. It was still received from a verified neighbor, so it is
            // processed normally — only replies to that neighbor will fail.
            if (event.message.group == RouterWire::ROUTER_PROTOCOL_GROUP) this->handleRouterControl(event.message);
            else                                                          this->handleRoutedMessage(event.message);
            break;
    }
}

void Router::handleRouterControl(const NetworkMessage& message) {
    // NEIGHBORS / IHAVE / GRAFT / PRUNE arrive with Plumtree (R-4) and the eager-set optimization (R-7)
    std::cerr << "Router: control subtype 0x" << std::hex << message.subtype << std::dec << " from " << shortPeerId(message.source) << " not handled yet" << std::endl;
}

void Router::handleRoutedMessage(const NetworkMessage& message) {
    RoutedMessage routed;
    const RoutedMessageStatus status = RouterWire::decode(message.group, message.subtype, message.payload, std::chrono::system_clock::now(), routed);
    if (status != RoutedMessageStatus::Success) {
        std::cerr << "Router: routed message from " << shortPeerId(message.source) << " rejected (status " << static_cast<int>(status) << ")" << std::endl;
        return;
    }
    // Forwarding and local delivery start with BROADCAST in R-3
    std::cerr << "Router: routed message " << std::hex << routed.msgId << std::dec << " from " << shortPeerId(message.source) << " decoded, routing not implemented yet" << std::endl;
}

} // namespace invilite::Mesh
