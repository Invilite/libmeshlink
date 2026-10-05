#include "meshlink/router.h"
#include "meshlink/network.h"
#include "meshlink/thread_safe_queue.h"
#include "meshlink/thread_signals.h"
#include "transport/platform.h"

#include <botan/system_rng.h>

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <variant>

namespace invilite::Mesh {

namespace {
    constexpr std::chrono::milliseconds EVENT_WAIT{100};                            // bounds how long stop() waits for the loop to notice
    constexpr std::chrono::milliseconds PENDING_RETRY_INTERVAL{100};                // how often parked messages look for their sender's record

    std::string shortPeerId(const PeerId& id) {
        char buf[13];
        std::snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x%02x", id[0], id[1], id[2], id[3], id[4], id[5]);
        return buf;
    }

    uint64_t randomMessageId() {
        uint64_t id = 0;
        Botan::system_rng().randomize(reinterpret_cast<uint8_t*>(&id), sizeof(id));
        return id;
    }

    uint32_t currentUnixSeconds() {
        return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    }
}

struct Router::Event {
    struct NeighborConnected    { PeerId peerId; };
    struct NeighborDisconnected { PeerId peerId; };
    struct FrameReceived        { NetworkMessage message; };
    struct BroadcastRequested   { RoutedMessage message; };                         // built and signed by Router::broadcast

    std::variant<NeighborConnected, NeighborDisconnected, FrameReceived, BroadcastRequested> content;
};

// The only object Network holds: it owns the queue, so Network may outlive the Router without dangling.
// Every callback copies the event into the queue and returns — no routing work on Network's threads.
class Router::EventInbox : public NetworkEventListener {
public:
    void onPeerConnected(const PeerIdentity& identity) override    { this->events.push({ Event::NeighborConnected{ identity.getPeerId() } }); }
    void onPeerDisconnected(const PeerId& peerId) override         { this->events.push({ Event::NeighborDisconnected{ peerId } }); }
    void onMessageReceived(const NetworkMessage& message) override { this->events.push({ Event::FrameReceived{ message } }); }

    ThreadSafeQueue<Event> events;
};

Router::Router(Network& network, std::shared_ptr<PeerDirectory> peerDirectory, std::shared_ptr<LocalIdentity> selfIdentity, RouterConfig config)
    : network(network), peerDirectory(std::move(peerDirectory)), selfIdentity(std::move(selfIdentity)), config(config),
      inbox(std::make_shared<EventInbox>()), seenMessages(config.duplicateWindow, config.duplicateCacheCapacity) {}

Router::~Router() {
    this->stop();
}

void Router::start() {
    if (this->running.exchange(true)) return;

    // Drop anything a previous run left behind, then register — events from now on are kept
    this->inbox->events.reopen();
    this->pendingVerifications.clear();
    this->unknownModeReportedAt.clear();
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

std::optional<uint64_t> Router::broadcast(uint8_t group, uint16_t subtype, std::vector<uint8_t> payload, RoutingMode mode) {
    if (!this->running.load() || group > RouterWire::MAX_ROUTED_GROUP || !RouterWire::reachesEveryNode(mode) || this->config.broadcastTtl == 0) return std::nullopt;

    RoutedMessage message;
    message.group             = group;
    message.subtype           = subtype;
    message.mode              = mode;
    message.ttlInitial        = this->config.broadcastTtl;
    message.ttlRemaining      = this->config.broadcastTtl;
    message.msgId             = randomMessageId();
    message.sentAtUnixSeconds = currentUnixSeconds();
    message.sender            = this->selfIdentity->getPeerId();
    message.payload           = std::move(payload);
    message.signature         = this->selfIdentity->sign(RouterWire::bytesToSign(message));    // Ed25519 off the Router thread

    const uint64_t msgId = message.msgId;
    this->inbox->events.push({ Event::BroadcastRequested{ std::move(message) } });
    return msgId;
}

void Router::addListener(std::shared_ptr<RouterEventListener> listener) {
    if (!listener) return;
    std::unique_lock lock(this->listenersMutex);
    this->listeners.push_back(std::move(listener));
}

void Router::removeListener(const std::shared_ptr<RouterEventListener>& listener) {
    std::unique_lock lock(this->listenersMutex);
    std::erase(this->listeners, listener);
}

std::vector<PeerId> Router::getNeighbors() const {
    return this->neighborsSnapshot();
}

RouterStatistics Router::getStatistics() const {
    return { this->fullMessagesSent.load(), this->duplicatesDropped.load() };
}

std::vector<PeerId> Router::neighborsSnapshot() const {
    std::lock_guard lock(this->neighborsMutex);
    return { this->neighbors.begin(), this->neighbors.end() };
}

void Router::routerLoop() {
    blockSigpipeInCurrentThread();

    while (this->running.load()) {
        auto event = this->inbox->events.waitPop(EVENT_WAIT);
        if (event) this->processEvent(*event);
        // On a timer, not after every event: the scan costs a directory lookup per parked message
        if (!this->pendingVerifications.empty() && std::chrono::steady_clock::now() >= this->nextPendingRetryAt) {
            this->retryPendingVerifications();
            this->nextPendingRetryAt = std::chrono::steady_clock::now() + PENDING_RETRY_INTERVAL;
        }
    }
}

void Router::processEvent(Event& event) {
    std::visit([this](auto& content) {
        using T = std::decay_t<decltype(content)>;
        if constexpr (std::is_same_v<T, Event::NeighborConnected>) {
            std::lock_guard lock(this->neighborsMutex);
            this->neighbors.insert(content.peerId);
        } else if constexpr (std::is_same_v<T, Event::NeighborDisconnected>) {
            this->unknownModeReportedAt.erase(content.peerId);
            std::lock_guard lock(this->neighborsMutex);
            this->neighbors.erase(content.peerId);
        } else if constexpr (std::is_same_v<T, Event::FrameReceived>) {
            // Until the Dispatch thread goes (C6), messages travel a different thread than disconnects: a message from a
            // neighbor may arrive after its disconnect event. It was still received from a verified neighbor, so it is
            // processed normally — only replies to that neighbor will fail.
            if (RouterWire::carriesRoutingHeader(content.message.group, content.message.subtype)) this->handleRoutedMessage(content.message);
            else                                                                                  this->handleRouterControl(content.message);
        } else {
            this->sendOwnBroadcast(content.message);
        }
    }, event.content);
}

void Router::handleRouterControl(const NetworkMessage& message) {
    if (message.subtype == RouterWire::SUBTYPE_UNKNOWN_DELIVERY_MODE) {
        UnknownDeliveryModeReport report;
        if (!RouterWire::decodeUnknownDeliveryMode(message.payload, report)) {
            std::cerr << "Router: malformed UNKNOWN_DELIVERY_MODE from " << shortPeerId(message.source) << std::endl;
            return;
        }
        // Informational: the mode is signed, so the message cannot be resent in another one (docs/router.md 3.4)
        std::cerr << "Router: " << shortPeerId(message.source) << " does not know mode 0x" << std::hex << static_cast<int>(report.mode)
                  << " of message " << report.message.msgId << std::dec << " from " << shortPeerId(report.message.sender) << std::endl;
        return;
    }
    // IHAVE / GRAFT / PRUNE arrive with Plumtree (R-4b), NEIGHBORS with the eager-set optimization (R-7)
    std::cerr << "Router: control subtype 0x" << std::hex << message.subtype << std::dec << " from " << shortPeerId(message.source) << " not handled yet" << std::endl;
}

// Tell the neighbor its message went no further here. Bounded per neighbor and mode: a flood of unknown-mode messages
// must not turn into a flood of replies.
void Router::reportUnknownMode(const RoutedMessage& message, const PeerId& receivedFrom) {
    {
        // A message may arrive after its neighbor's disconnect (until C6): no reply, and no entry that nobody would erase
        std::lock_guard lock(this->neighborsMutex);
        if (!this->neighbors.contains(receivedFrom)) return;
    }
    const auto now = std::chrono::steady_clock::now();
    auto& lastReport = this->unknownModeReportedAt[receivedFrom][static_cast<uint8_t>(message.mode) & 0x0F];
    if (lastReport && now - *lastReport < this->config.unknownModeReportInterval) return;
    lastReport = now;
    this->network.sendToPeer(receivedFrom, RouterWire::encodeUnknownDeliveryMode({ static_cast<uint8_t>(message.mode), { message.sender, message.msgId } }));
}

void Router::handleRoutedMessage(const NetworkMessage& message) {
    RoutedMessage routed;
    const RoutedMessageStatus status = RouterWire::decode(message.group, message.subtype, message.payload, std::chrono::system_clock::now(), routed, this->config.maxClockSkew);
    if (status == RoutedMessageStatus::UnknownMode) {                              // neither delivered nor forwarded
        this->reportUnknownMode(routed, message.source);
        return;
    }
    if (status != RoutedMessageStatus::Success) {
        std::cerr << "Router: routed message from " << shortPeerId(message.source) << " rejected (status " << static_cast<int>(status) << ")" << std::endl;
        return;
    }

    if (RouterWire::reachesEveryNode(routed.mode)) {                               // Group 0xFE never travels to every node (decode refuses it)
        this->handleIncomingBroadcast(std::move(routed), message.source);
        return;
    }
    // Point-to-point modes and routed Router messages start in R-5
    std::cerr << "Router: routed message mode " << static_cast<int>(routed.mode) << " from " << shortPeerId(message.source) << " not handled yet" << std::endl;
}

// docs/router.md 4.1 for BROADCAST: duplicate → sender's key → signature → seen → deliver → forward
void Router::handleIncomingBroadcast(RoutedMessage message, const PeerId& receivedFrom) {
    // Our own message coming back is a duplicate too — also after a restart emptied the memory (no record of ourselves
    // to verify against, so without this it would only waste a PEX_REQUEST and a verification slot)
    if (message.sender == this->selfIdentity->getPeerId() || this->isAlreadySeen(message)) {   // Plumtree reacts here in R-4
        ++this->duplicatesDropped;
        return;
    }

    const auto senderEntry = this->peerDirectory->findPeer(message.sender);
    if (!senderEntry) {
        this->awaitSenderRecord(std::move(message), receivedFrom);
        return;
    }
    this->acceptBroadcastWithKey(std::move(message), receivedFrom, senderEntry->record.ed25519Pub);
}

// The neighbor that forwarded the message verified it first, so it holds the sender's record: ask it (PEX_REQUEST) and
// park the message for a short while. Bounded — a flood of messages from unknown senders cannot grow memory.
void Router::awaitSenderRecord(RoutedMessage message, const PeerId& receivedFrom) {
    size_t fromThisNeighbor = 0;
    for (const PendingVerification& pending : this->pendingVerifications) {
        if (pending.message.sender == message.sender && pending.message.msgId == message.msgId) return;   // same message already waits
        if (pending.receivedFrom == receivedFrom) ++fromThisNeighbor;
    }
    if (this->pendingVerifications.size() >= this->config.pendingVerificationLimit || fromThisNeighbor >= this->config.pendingVerificationPerNeighbor) {
        std::cerr << "Router: broadcast from unknown " << shortPeerId(message.sender) << " dropped, verification queue full (from "
                  << shortPeerId(receivedFrom) << ")" << std::endl;
        return;
    }

    const bool alreadyRequested = std::any_of(this->pendingVerifications.begin(), this->pendingVerifications.end(),
                                              [&](const PendingVerification& p) { return p.message.sender == message.sender && p.receivedFrom == receivedFrom; });
    if (!alreadyRequested) this->network.requestPeerRecords(receivedFrom, { message.sender });

    this->pendingVerifications.push_back({ std::move(message), receivedFrom, std::chrono::steady_clock::now() + this->config.unknownSenderWait });
}

void Router::retryPendingVerifications() {
    const auto now = std::chrono::steady_clock::now();
    std::vector<PendingVerification> waiting;
    waiting.swap(this->pendingVerifications);

    for (PendingVerification& pending : waiting) {
        if (this->isAlreadySeen(pending.message)) continue;                        // another copy got through meanwhile

        if (const auto senderEntry = this->peerDirectory->findPeer(pending.message.sender)) {
            this->acceptBroadcastWithKey(std::move(pending.message), pending.receivedFrom, senderEntry->record.ed25519Pub);
        } else if (now >= pending.deadline) {
            std::cerr << "Router: broadcast from unknown " << shortPeerId(pending.message.sender) << " dropped, record did not arrive" << std::endl;
        } else {
            this->pendingVerifications.push_back(std::move(pending));
        }
    }
}

// Signature first, and only then "seen": a forgery must not occupy the msgId of the genuine message
void Router::acceptBroadcastWithKey(RoutedMessage message, const PeerId& receivedFrom, std::span<const uint8_t> senderEd25519Pub) {
    if (!RouterWire::verifySignature(message, senderEd25519Pub)) {
        std::cerr << "Router: broadcast " << std::hex << message.msgId << std::dec << " claiming sender " << shortPeerId(message.sender)
                  << " has an invalid signature, dropped (from " << shortPeerId(receivedFrom) << ")" << std::endl;
        return;
    }
    this->seenMessages.remember({ message.sender, message.msgId }, message.sentAtUnixSeconds, std::chrono::steady_clock::now());
    this->deliverLocally(message);
    this->forwardBroadcast(std::move(message), receivedFrom);
}

// Remembered, or possibly forgotten early because the duplicate memory overflowed — either way it must not count as new
bool Router::isAlreadySeen(const RoutedMessage& message) const {
    return this->seenMessages.contains({ message.sender, message.msgId }) || this->seenMessages.predatesEvictedKeys(message.sentAtUnixSeconds);
}

void Router::sendOwnBroadcast(const RoutedMessage& message) {
    this->seenMessages.remember({ message.sender, message.msgId }, message.sentAtUnixSeconds, std::chrono::steady_clock::now());   // echoes are dropped
    this->sendFullCopies(message, std::nullopt);
}

void Router::forwardBroadcast(RoutedMessage message, const PeerId& receivedFrom) {
    if (message.ttlRemaining <= 1) return;                                          // the next hop would receive TTL 0
    message.ttlRemaining -= 1;
    this->sendFullCopies(message, receivedFrom);
}

// The broadcast strategy's decision (docs/router.md 4.3). Never back to where the message came from, never to its
// originator. For BROADCAST, Plumtree (R-4b) narrows this to the eager neighbors and announces to the rest; until then
// both modes reaching every node are Flood.
std::vector<PeerId> Router::chooseFullCopyRecipients(const RoutedMessage& message, const std::optional<PeerId>& receivedFrom) const {
    std::vector<PeerId> recipients = this->neighborsSnapshot();
    std::erase_if(recipients, [&](const PeerId& neighbor) { return neighbor == receivedFrom || neighbor == message.sender; });
    return recipients;
}

void Router::sendFullCopies(const RoutedMessage& message, const std::optional<PeerId>& receivedFrom) {
    const std::vector<uint8_t> frame = RouterWire::encode(message);
    if (frame.empty()) return;
    for (const PeerId& neighbor : this->chooseFullCopyRecipients(message, receivedFrom)) {
        if (this->network.sendToPeer(neighbor, frame) > 0) ++this->fullMessagesSent;
    }
}

void Router::deliverLocally(const RoutedMessage& message) {
    RoutedDelivery delivery;
    delivery.sender       = message.sender;
    delivery.msgId        = message.msgId;
    delivery.group        = message.group;
    delivery.subtype      = message.subtype;
    delivery.mode         = message.mode;
    // The sender's first hop does not decrement; clamped because ttlInitial 255 with ttlRemaining 0 would wrap to 0
    delivery.hopsTraveled = static_cast<uint8_t>(std::min(message.ttlInitial - message.ttlRemaining + 1, 255));
    delivery.payload      = message.payload;

    std::vector<std::shared_ptr<RouterEventListener>> snapshot;
    {
        std::shared_lock lock(this->listenersMutex);
        snapshot = this->listeners;
    }
    for (const auto& listener : snapshot) {
        try {
            listener->onMessageDelivered(delivery);
        } catch (const std::exception& e) {
            std::cerr << "Router: listener->onMessageDelivered threw: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "Router: listener->onMessageDelivered threw unknown exception" << std::endl;
        }
    }
}

} // namespace invilite::Mesh
