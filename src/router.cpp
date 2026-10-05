#include "meshlink/router.h"
#include "meshlink/network.h"
#include "meshlink/thread_safe_queue.h"
#include "meshlink/thread_signals.h"
#include "transport/platform.h"

#include <botan/system_rng.h>

#include <algorithm>
#include <cstdio>
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

    // Uniform in [0, max] — spreads answers in time; not security-relevant
    std::chrono::milliseconds randomDelayUpTo(std::chrono::milliseconds max) {
        if (max.count() <= 0) return std::chrono::milliseconds(0);
        return std::chrono::milliseconds(randomMessageId() % (static_cast<uint64_t>(max.count()) + 1));
    }

    // The sender's first hop does not decrement; clamped because ttlInitial 255 with ttlRemaining 0 would wrap to 0
    uint8_t hopsTraveled(const RoutedMessage& message) {
        return static_cast<uint8_t>(std::min(message.ttlInitial - message.ttlRemaining + 1, 255));
    }

    // A source route this node may send along: at most 254 relays (the destination makes 255 hops), none of them this
    // node or the destination, none twice — anything else would loop or could never be walked
    bool isUsableSourceRoute(const std::vector<PeerId>& relays, const PeerId& self, const PeerId& destination) {
        if (relays.size() > 254) return false;
        std::unordered_set<PeerId, PeerIDHash> seen;
        for (const PeerId& relay : relays) {
            if (relay == self || relay == destination || !seen.insert(relay).second) return false;
        }
        return true;
    }

    // ROUTED (docs/router.md 4.2): nextHopIndex names the node receiving the message — a relay, or the destination when
    // the route is used up. Anyone else was not asked to handle it.
    bool namesThisNode(const RoutedMessage& message, const PeerId& self) {
        const SourceRoute& route = *message.sourceRoute;
        return route.nextHopIndex < route.hops.size() ? route.hops[route.nextHopIndex] == self : message.destination == self;
    }

    // The hop after the node holding the message (index already advanced past it)
    const PeerId& nextRoutedHop(const RoutedMessage& message) {
        const SourceRoute& route = *message.sourceRoute;
        return route.nextHopIndex < route.hops.size() ? route.hops[route.nextHopIndex] : *message.destination;
    }

    uint64_t currentUnixMs() {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    }

    // ms since `sentAtUnixMs` on our clock; clock skew could make it negative — then 0
    uint32_t offsetSince(uint64_t sentAtUnixMs) {
        const uint64_t now = currentUnixMs();
        return now <= sentAtUnixMs ? 0 : static_cast<uint32_t>(std::min<uint64_t>(now - sentAtUnixMs, UINT32_MAX));
    }

    uint32_t currentUnixSeconds() {
        return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    }
}

struct Router::Event {
    struct NeighborConnected    { PeerId peerId; };
    struct NeighborDisconnected { PeerId peerId; };
    struct FrameReceived        { NetworkMessage message; };
    struct SendRequested        { RoutedMessage message; };                         // built (and signed when required) by broadcast() / send()

    std::variant<NeighborConnected, NeighborDisconnected, FrameReceived, SendRequested> content;
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

Router::Router(Network& network, std::shared_ptr<PeerDirectory> peerDirectory, std::shared_ptr<LocalIdentity> selfIdentity, RouterConfig config,
               std::shared_ptr<Logger> logger)
    : network(network), peerDirectory(std::move(peerDirectory)), selfIdentity(std::move(selfIdentity)), config(config),
      log(logger ? std::move(logger) : network.getLogger(), "Router"),
      inbox(std::make_shared<EventInbox>()), seenMessages(config.duplicateWindow, config.duplicateCacheCapacity), unsignedSeenMessages(config.duplicateWindow, config.duplicateCacheCapacity),
      plumtree(config.plumtree), broadcastCache(config.graftCacheRetention, config.graftCacheByteLimit), routes(config.routes) {}

Router::~Router() {
    this->stop();
}

void Router::start() {
    if (this->running.exchange(true)) return;

    // Drop anything a previous run left behind, then register — events from now on are kept
    this->inbox->events.reopen();
    this->pendingVerifications.clear();
    this->unknownModeReportedAt.clear();
    this->unicastAcksByNeighbor.clear();
    this->routeErrorReportedAt.clear();
    this->awaitedReplies.clear();
    this->awaitedReplyOrder.clear();
    this->plumtree       = PlumtreeState(this->config.plumtree);
    this->broadcastCache = BroadcastCache(this->config.graftCacheRetention, this->config.graftCacheByteLimit);
    {
        std::lock_guard lock(this->routesMutex);
        this->routes = RouteTable(this->config.routes);
    }
    this->network.addListener(this->inbox);

    // Seed after registering, before the loop drains anything. A peer that connects or leaves around this point shows up
    // in the queue as well, and queued events are applied after the seed — so the final view is right either way.
    {
        std::lock_guard lock(this->neighborsMutex);
        this->neighbors.clear();
        for (const PeerId& peerId : this->network.getConnectedPeers()) {
            this->neighbors.insert(peerId);
            this->plumtree.addLink(peerId);
        }
        this->presencePending = !this->neighbors.empty() && this->config.announcePresence && this->config.broadcastTtl > 0;
        this->lastPresenceAt.reset();
        this->presenceRepliedAt.clear();
        this->scheduledPresenceReplies.clear();
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

std::optional<uint64_t> Router::broadcast(uint8_t group, uint16_t subtype, std::vector<uint8_t> payload, RoutingMode mode, SendOptions options) {
    if (!this->running.load() || group > RouterWire::MAX_ROUTED_GROUP || !RouterWire::reachesEveryNode(mode) || this->config.broadcastTtl == 0) return std::nullopt;

    RoutedMessage message;
    message.group             = group;
    message.subtype           = subtype;
    message.mode              = mode;
    message.ackRequested      = options.ackRequested;
    message.ttlInitial        = this->config.broadcastTtl;
    message.ttlRemaining      = this->config.broadcastTtl;
    message.msgId             = randomMessageId();
    message.sentAtUnixSeconds = currentUnixSeconds();
    message.sender            = this->selfIdentity->getPeerId();
    message.payload           = std::move(payload);
    message.signature         = this->selfIdentity->sign(RouterWire::bytesToSign(message));    // Ed25519 off the Router thread

    const uint64_t msgId = message.msgId;
    this->inbox->events.push({ Event::SendRequested{ std::move(message) } });
    return msgId;
}

std::optional<uint64_t> Router::recordRoute(const PeerId& destination) {
    if (!this->running.load() || this->config.unicastTtl == 0 || destination == this->selfIdentity->getPeerId()) return std::nullopt;
    RoutedMessage probe = this->buildRouterMessage(destination, RouterWire::SUBTYPE_RECORD_ROUTE, RouterWire::encodeRecordRoutePayload({ currentUnixMs(), {} }));
    const uint64_t msgId = probe.msgId;
    this->inbox->events.push({ Event::SendRequested{ std::move(probe) } });       // signed here, off the Router thread
    return msgId;
}

std::optional<uint64_t> Router::send(const PeerId& destination, uint8_t group, uint16_t subtype, std::vector<uint8_t> payload, SendOptions options) {
    if (!this->running.load() || group > RouterWire::MAX_ROUTED_GROUP || this->config.unicastTtl == 0 || destination == this->selfIdentity->getPeerId()) return std::nullopt;

    RoutedMessage message;
    message.group             = group;
    message.subtype           = subtype;
    message.mode              = RoutingMode::Unicast;
    message.ackRequested      = options.ackRequested;
    message.ttlInitial        = this->config.unicastTtl;
    message.ttlRemaining      = this->config.unicastTtl;
    message.msgId             = randomMessageId();
    message.sentAtUnixSeconds = currentUnixSeconds();
    message.sender            = this->selfIdentity->getPeerId();
    message.destination       = destination;
    message.payload           = std::move(payload);

    const uint64_t msgId = message.msgId;
    this->inbox->events.push({ Event::SendRequested{ std::move(message) } });
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

std::optional<uint64_t> Router::sendAlongRoute(const PeerId& destination, std::vector<PeerId> relays, uint8_t group, uint16_t subtype, std::vector<uint8_t> payload, SendOptions options) {
    const PeerId& self = this->selfIdentity->getPeerId();
    if (!this->running.load() || group > RouterWire::MAX_ROUTED_GROUP || destination == self || !isUsableSourceRoute(relays, self, destination)) return std::nullopt;
    {
        std::lock_guard lock(this->neighborsMutex);
        if (!this->neighbors.contains(relays.empty() ? destination : relays.front())) return std::nullopt;
    }

    RoutedMessage message;
    message.group             = group;
    message.subtype           = subtype;
    message.mode              = RoutingMode::Routed;
    message.ackRequested      = options.ackRequested;
    message.ttlInitial        = static_cast<uint8_t>(std::max<size_t>(this->config.unicastTtl, relays.size() + 1));   // enough to walk the whole route
    message.ttlRemaining      = message.ttlInitial;
    message.msgId             = randomMessageId();
    message.sentAtUnixSeconds = currentUnixSeconds();
    message.sender            = self;
    message.destination       = destination;
    message.sourceRoute       = SourceRoute{ 0, std::move(relays) };
    message.payload           = std::move(payload);

    const uint64_t msgId = message.msgId;
    this->inbox->events.push({ Event::SendRequested{ std::move(message) } });
    return msgId;
}

RouterStatistics Router::getStatistics() const {
    return { this->fullMessagesSent.load(), this->duplicatesDropped.load(), this->announcementsSent.load(), this->graftsSent.load(), this->prunesSent.load(),
             this->localFloods.load(), this->acksSent.load(), this->routedForwarded.load(), this->routeErrorsSent.load(), this->presenceSent.load(), this->presenceRepliesSent.load() };
}

std::vector<RouteCandidate> Router::getRouteCandidates(const PeerId& destination) const {
    std::lock_guard lock(this->routesMutex);
    return this->routes.candidates(destination);
}

std::vector<PeerId> Router::neighborsSnapshot() const {
    std::lock_guard lock(this->neighborsMutex);
    return { this->neighbors.begin(), this->neighbors.end() };
}

void Router::routerLoop() {
    blockSigpipeInCurrentThread();

    while (this->running.load()) {
        // Wake for the next Plumtree deadline (IHAVE batch, GRAFT) — not only for events
        auto wait = EVENT_WAIT;
        if (const auto deadline = this->plumtree.nextDeadline()) {
            const auto untilDeadline = std::chrono::ceil<std::chrono::milliseconds>(*deadline - std::chrono::steady_clock::now());
            wait = std::clamp(untilDeadline, std::chrono::milliseconds(0), EVENT_WAIT);
        }
        auto event = this->inbox->events.waitPop(wait);
        if (event) this->processEvent(*event);
        this->runPlumtreeTimers(std::chrono::steady_clock::now());
        // On a timer, not after every event: the scan costs a directory lookup per parked message
        if (!this->pendingVerifications.empty() && std::chrono::steady_clock::now() >= this->nextPendingRetryAt) {
            this->retryPendingVerifications();
            this->nextPendingRetryAt = std::chrono::steady_clock::now() + PENDING_RETRY_INTERVAL;
        }
        this->announcePresenceWhenDue(std::chrono::steady_clock::now());
        this->sendDuePresenceReplies(std::chrono::steady_clock::now());
    }
}

// PRESENCE (docs/router.md 3.3): our Router tells every other Router "I am here" when a neighbor appears — every node then
// knows the way back to us (an ACK for unsigned data needs one, review R-5 I4) without the application having to
// broadcast. At most once per presenceMinInterval; a neighbor arriving inside the interval is caught up when it ends, so
// a later part of the network learns of us too.
// A PRESENCE teaches us the way to its sender; our answer teaches the sender the way back to us — a node joining later
// learns of nodes that get no new neighbor (and so send no PRESENCE). At most once per presenceMinInterval to the same
// node. Every node answers the same PRESENCE, so the answer waits a random part of presenceReplySpread: a joiner, which
// lacks most answerers' records, verifies them through a small queue per neighbor — a burst would overflow it, and the
// lost answers would not come again for a whole interval (review PRESENCE I1).
void Router::answerPresence(const PeerId& sender) {
    const auto now = std::chrono::steady_clock::now();
    const auto replied = this->presenceRepliedAt.find(sender);
    if (replied != this->presenceRepliedAt.end() && now - replied->second < this->config.presenceMinInterval) return;
    if (this->scheduledPresenceReplies.size() >= MAX_SCHEDULED_PRESENCE_REPLIES) return;
    for (const auto& scheduled : this->scheduledPresenceReplies) if (scheduled.second == sender) return;
    this->scheduledPresenceReplies.emplace_back(now + randomDelayUpTo(this->config.presenceReplySpread), sender);
}

// Due answers go out within presenceRepliesPerSecond for the whole node (one PRESENCE makes every node answer — review
// PRESENCE I2); the rest wait for the next second. Over a known way only, never by flooding.
void Router::sendDuePresenceReplies(std::chrono::steady_clock::time_point now) {
    if (this->scheduledPresenceReplies.empty()) return;
    if (now - this->presenceReplyWindowStart >= std::chrono::seconds(1)) {
        this->presenceReplyWindowStart = now;
        this->presenceRepliesInWindow  = 0;
    }
    for (auto it = this->scheduledPresenceReplies.begin(); it != this->scheduledPresenceReplies.end();) {
        if (it->first > now) { ++it; continue; }
        if (this->presenceRepliesInWindow >= this->config.presenceRepliesPerSecond) return;   // the rest next second
        const PeerId sender = it->second;
        it = this->scheduledPresenceReplies.erase(it);
        if (!this->knowsWayTo(sender)) continue;                                    // its route ended meanwhile
        ++this->presenceRepliesInWindow;
        this->rememberPresenceReply(sender, now);
        ++this->presenceRepliesSent;
        this->sendOwnRouterMessage(this->buildRouterMessage(sender, RouterWire::SUBTYPE_PRESENCE_REPLY, {}));
    }
}

// Bounded: when full, expired entries go, then the oldest — a flood of senders must not lock honest joiners out (review PRESENCE M3)
void Router::rememberPresenceReply(const PeerId& sender, std::chrono::steady_clock::time_point now) {
    if (this->presenceRepliedAt.size() >= MAX_PRESENCE_REPLY_MEMORY && !this->presenceRepliedAt.contains(sender)) {
        std::erase_if(this->presenceRepliedAt, [&](const auto& entry) { return now - entry.second >= this->config.presenceMinInterval; });
        if (this->presenceRepliedAt.size() >= MAX_PRESENCE_REPLY_MEMORY) {
            this->presenceRepliedAt.erase(std::min_element(this->presenceRepliedAt.begin(), this->presenceRepliedAt.end(), [](const auto& a, const auto& b) { return a.second < b.second; }));
        }
    }
    this->presenceRepliedAt[sender] = now;
}

void Router::announcePresenceWhenDue(std::chrono::steady_clock::time_point now) {
    if (!this->presencePending || (this->lastPresenceAt && now - *this->lastPresenceAt < this->config.presenceMinInterval)) return;
    this->presencePending = false;
    if (this->neighborsSnapshot().empty()) return;                                  // the neighbor left again: nobody to tell, the interval stays unused (M1)
    this->lastPresenceAt  = now;

    RoutedMessage presence;
    presence.group             = RouterWire::ROUTER_PROTOCOL_GROUP;
    presence.subtype           = RouterWire::SUBTYPE_PRESENCE;
    presence.mode              = RoutingMode::Broadcast;
    presence.ttlInitial        = this->config.broadcastTtl;
    presence.ttlRemaining      = this->config.broadcastTtl;
    presence.msgId             = randomMessageId();
    presence.sentAtUnixSeconds = currentUnixSeconds();
    presence.sender            = this->selfIdentity->getPeerId();
    presence.signature         = this->selfIdentity->sign(RouterWire::bytesToSign(presence));   // once a minute at most: fine on this thread
    ++this->presenceSent;
    this->sendOwnBroadcast(presence);
}

void Router::processEvent(Event& event) {
    std::visit([this](auto& content) {
        using T = std::decay_t<decltype(content)>;
        if constexpr (std::is_same_v<T, Event::NeighborConnected>) {
            this->plumtree.addLink(content.peerId);
            std::lock_guard lock(this->neighborsMutex);
            // Only a neighbor new to us: the start() seed and a queued event may name the same one (M2)
            if (this->neighbors.insert(content.peerId).second && this->config.announcePresence && this->config.broadcastTtl > 0) this->presencePending = true;
        } else if constexpr (std::is_same_v<T, Event::NeighborDisconnected>) {
            this->unknownModeReportedAt.erase(content.peerId);
            this->unicastAcksByNeighbor.erase(content.peerId);
            this->routeErrorReportedAt.erase(content.peerId);
            this->broadcastCache.forgetNeighbor(content.peerId);
            {
                std::lock_guard lock(this->routesMutex);
                this->routes.forgetNeighbor(content.peerId);                        // routes do not expire — they end with their neighbor
            }
            {
                std::lock_guard lock(this->neighborsMutex);
                this->neighbors.erase(content.peerId);
            }
            // Fast repair (docs/router.md 4.3): an eager link is gone, ask every lazy one for full copies again
            for (const PeerId& lazyLink : this->plumtree.removeLink(content.peerId)) this->sendGraft(lazyLink, {});
        } else if constexpr (std::is_same_v<T, Event::FrameReceived>) {
            // Until the Dispatch thread goes (C6), messages travel a different thread than disconnects: a message from a
            // neighbor may arrive after its disconnect event. It was still received from a verified neighbor, so it is
            // processed normally — only replies to that neighbor will fail, and it teaches no route (learnRoute).
            if (RouterWire::carriesRoutingHeader(content.message.group, content.message.subtype)) this->handleRoutedMessage(content.message);
            else                                                                                  this->handleRouterControl(content.message);
        } else if (RouterWire::reachesEveryNode(content.message.mode)) {
            if (content.message.ackRequested) this->awaitReply(content.message.msgId, std::nullopt, true);   // every node answers
            this->sendOwnBroadcast(content.message);
        } else {
            const bool isProbe = content.message.group == RouterWire::ROUTER_PROTOCOL_GROUP && content.message.subtype == RouterWire::SUBTYPE_RECORD_ROUTE;
            const bool isRouted = content.message.mode == RoutingMode::Routed;
            if (content.message.ackRequested || isProbe || isRouted) {
                // A ROUTED message waits for a possible ROUTE_ERROR too — from a relay of its route only
                this->awaitReply(content.message.msgId, content.message.destination, content.message.ackRequested || isProbe,
                                 isRouted ? std::optional(content.message.sourceRoute->hops) : std::nullopt);
            }
            this->rememberSeen(content.message);
            if (isRouted) this->forwardRouted(content.message, std::nullopt);
            else          this->forwardUnicast(content.message, std::nullopt);
        }
    }, event.content);
}

void Router::handleRouterControl(const NetworkMessage& message) {
    switch (message.subtype) {
        case RouterWire::SUBTYPE_IHAVE: this->handleAnnouncement(message.source, message.payload); return;
        case RouterWire::SUBTYPE_GRAFT: this->handleGraft(message.source, message.payload); return;
        case RouterWire::SUBTYPE_PRUNE:
            if (RouterWire::decodePrune(message.payload)) this->plumtree.onPrune(message.source);
            else this->log.formatRateLimited(this->routerThreadLogLimiter, "malformed PRUNE:" + shortPeerId(message.source), LogLevel::Warning, "malformed PRUNE from {}", shortPeerId(message.source));
            return;
        case RouterWire::SUBTYPE_UNKNOWN_DELIVERY_MODE: {
            UnknownDeliveryModeReport report;
            if (!RouterWire::decodeUnknownDeliveryMode(message.payload, report)) {
                this->log.formatRateLimited(this->routerThreadLogLimiter, "malformed UNKNOWN_DELIVERY_MODE:" + shortPeerId(message.source), LogLevel::Warning, "malformed UNKNOWN_DELIVERY_MODE from {}", shortPeerId(message.source));
                return;
            }
            // Informational: the mode is signed, so the message cannot be resent in another one (docs/router.md 3.4)
            this->log.formatRateLimited(this->routerThreadLogLimiter, "unknown mode report:" + shortPeerId(message.source), LogLevel::Notice, "{} does not know mode 0x{:x} of message {:x} from {}", shortPeerId(message.source), static_cast<int>(report.mode), report.message.msgId, shortPeerId(report.message.sender));
            return;
        }
        default:
            // NEIGHBORS arrives with the eager-set optimization (R-7)
            this->log.formatRateLimited(this->routerThreadLogLimiter, "unhandled control subtype:" + shortPeerId(message.source), LogLevel::Warning, "control subtype 0x{:04x} from {} not handled", message.subtype, shortPeerId(message.source));
    }
}

// IHAVE: keys we have not seen are missing — Plumtree GRAFTs them if they do not arrive. A key parked for verification
// counts as missing too: the parked copy may be a forgery that only took the slot first.
void Router::handleAnnouncement(const PeerId& from, std::span<const uint8_t> payload) {
    std::vector<RoutedMessageKey> keys;
    if (!RouterWire::decodeIhave(payload, keys)) {
        this->log.formatRateLimited(this->routerThreadLogLimiter, "malformed IHAVE:" + shortPeerId(from), LogLevel::Warning, "malformed IHAVE from {}", shortPeerId(from));
        return;
    }
    std::erase_if(keys, [this](const RoutedMessageKey& key) {
        return key.sender == this->selfIdentity->getPeerId() || this->seenMessages.contains(key);
    });
    this->plumtree.onAnnouncement(from, keys, std::chrono::steady_clock::now());
}

// GRAFT: the neighbor is eager from now on and gets the asked messages we hold — each at most once (BroadcastCache)
void Router::handleGraft(const PeerId& from, std::span<const uint8_t> payload) {
    std::vector<RoutedMessageKey> keys;
    if (!RouterWire::decodeGraft(payload, keys)) {
        this->log.formatRateLimited(this->routerThreadLogLimiter, "malformed GRAFT:" + shortPeerId(from), LogLevel::Warning, "malformed GRAFT from {}", shortPeerId(from));
        return;
    }
    this->plumtree.onGraft(from);
    for (const RoutedMessageKey& key : keys) {
        // TTL 0: it ended here and was never announced — serving it would carry it a hop past its TTL
        const RoutedMessage* held = this->broadcastCache.find(key);
        if (!held || held->ttlRemaining == 0 || this->broadcastCache.wasSentTo(key, from)) continue;
        if (this->sendFullCopy(from, RouterWire::encode(*held))) this->broadcastCache.markSentTo(key, from);
    }
}

void Router::sendGraft(const PeerId& neighbor, const std::vector<RoutedMessageKey>& keys) {
    // Empty GRAFT is one frame; longer lists go in frames of at most 255 keys
    size_t offset = 0;
    do {
        const size_t count = std::min(keys.size() - offset, RouterWire::MAX_KEYS_PER_CONTROL_MESSAGE);
        if (this->network.sendToPeer(neighbor, RouterWire::encodeGraft(std::span(keys).subspan(offset, count))) > 0) ++this->graftsSent;
        offset += count;
    } while (offset < keys.size());
}

void Router::sendAnnouncements(const PeerId& neighbor, const std::vector<RoutedMessageKey>& keys) {
    for (size_t offset = 0; offset < keys.size(); offset += RouterWire::MAX_KEYS_PER_CONTROL_MESSAGE) {
        const size_t count = std::min(keys.size() - offset, RouterWire::MAX_KEYS_PER_CONTROL_MESSAGE);
        if (this->network.sendToPeer(neighbor, RouterWire::encodeIhave(std::span(keys).subspan(offset, count))) > 0) this->announcementsSent += count;
    }
}

void Router::runPlumtreeTimers(std::chrono::steady_clock::time_point now) {
    for (const auto& [neighbor, keys] : this->plumtree.takeDueGrafts(now))         this->sendGraft(neighbor, keys);
    for (const auto& [neighbor, keys] : this->plumtree.takeDueAnnouncements(now))  this->sendAnnouncements(neighbor, keys);
    this->broadcastCache.dropExpired(now);
    this->dropExpiredAwaitedReplies(now);
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
        this->log.formatRateLimited(this->routerThreadLogLimiter, "routed message rejected:" + shortPeerId(message.source), LogLevel::Warning, "routed message from {} rejected (status {})", shortPeerId(message.source), static_cast<int>(status));
        return;
    }

    // A source-routed message names the node meant to receive it; checked before any signature work
    if (routed.mode == RoutingMode::Routed && !namesThisNode(routed, this->selfIdentity->getPeerId())) {
        this->log.formatRateLimited(this->routerThreadLogLimiter, "routed to another hop:" + shortPeerId(message.source), LogLevel::Warning, "ROUTED message from {} names another hop, dropped", shortPeerId(message.source));
        return;
    }
    // Signed: broadcasts (Group 0xFE never travels to every node — decode refuses it) and the Router's own messages
    if (RouterWire::requiresSignature(routed.group, routed.mode)) {
        this->handleIncomingSigned(std::move(routed), message.source);
        return;
    }
    if (routed.mode == RoutingMode::Unicast) this->handleIncomingUnicast(std::move(routed), message.source);
    else                                     this->handleIncomingRouted(std::move(routed), message.source);
}

// docs/router.md 4.1 for signed messages: duplicate → sender's key → signature → seen → deliver / forward
void Router::handleIncomingSigned(RoutedMessage message, const PeerId& receivedFrom) {
    // Our own message coming back is a duplicate too — also after a restart emptied the memory (no record of ourselves
    // to verify against, so without this it would only waste a PEX_REQUEST and a verification slot)
    if (message.sender == this->selfIdentity->getPeerId() || this->isAlreadySeen(message)) {
        ++this->duplicatesDropped;
        if (message.mode == RoutingMode::Broadcast) this->reactToBroadcastDuplicate(message, receivedFrom);
        return;
    }

    const auto senderEntry = this->peerDirectory->findPeer(message.sender);
    if (!senderEntry) {
        this->awaitSenderRecord(std::move(message), receivedFrom);
        return;
    }
    this->acceptWithKey(std::move(message), receivedFrom, senderEntry->record.ed25519Pub);
}

// The neighbor that forwarded the message verified it first, so it holds the sender's record: ask it (PEX_REQUEST) and
// park the message for a short while. Bounded — a flood of messages from unknown senders cannot grow memory.
void Router::awaitSenderRecord(RoutedMessage message, const PeerId& receivedFrom) {
    size_t fromThisNeighbor = 0;
    for (const PendingVerification& pending : this->pendingVerifications) {
        // The same message from the same neighbor already waits. From another neighbor it waits separately: the copy
        // parked first may be a forgery, and only the honest neighbor holds the record to verify the genuine one.
        if (pending.message.sender == message.sender && pending.message.msgId == message.msgId && pending.receivedFrom == receivedFrom) return;
        if (pending.receivedFrom == receivedFrom) ++fromThisNeighbor;
    }
    if (this->pendingVerifications.size() >= this->config.pendingVerificationLimit || fromThisNeighbor >= this->config.pendingVerificationPerNeighbor) {
        this->log.formatRateLimited(this->routerThreadLogLimiter, "verification queue full:" + shortPeerId(receivedFrom), LogLevel::Warning, "message from unknown {} dropped, verification queue full (from {})", shortPeerId(message.sender), shortPeerId(receivedFrom));
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
            this->acceptWithKey(std::move(pending.message), pending.receivedFrom, senderEntry->record.ed25519Pub);
        } else if (now >= pending.deadline) {
            this->log.format(LogLevel::Info, "message from unknown {} dropped, record did not arrive", shortPeerId(pending.message.sender));
        } else {
            this->pendingVerifications.push_back(std::move(pending));
        }
    }
}

// Signature first, and only then "seen": a forgery must not occupy the msgId of the genuine message
void Router::acceptWithKey(RoutedMessage message, const PeerId& receivedFrom, std::span<const uint8_t> senderEd25519Pub) {
    if (!RouterWire::verifySignature(message, senderEd25519Pub)) {
        this->log.formatRateLimited(this->routerThreadLogLimiter, "invalid signature:" + shortPeerId(receivedFrom), LogLevel::Warning, "message {:x} claiming sender {} has an invalid signature, dropped (from {})", message.msgId, shortPeerId(message.sender), shortPeerId(receivedFrom));
        return;
    }
    this->rememberSeen(message);
    if (RouterWire::reachesEveryNode(message.mode)) this->acceptVerifiedBroadcast(message, receivedFrom);
    else                                            this->acceptVerifiedRouterMessage(std::move(message), receivedFrom);
}

void Router::acceptVerifiedBroadcast(const RoutedMessage& message, const PeerId& receivedFrom) {
    // D6: the first copy came by the fastest path — the sender is reachable over that neighbor (signed, so D5 holds)
    this->learnRoute(message.sender, receivedFrom, hopsTraveled(message), RouteEvidence::Broadcast);
    if (message.group != RouterWire::ROUTER_PROTOCOL_GROUP) {                       // PRESENCE is for Routers, not applications
        this->deliverLocally(message, true);                                        // signature checked
        if (message.ackRequested) this->sendAck(message);                           // every node is an addressee
    } else if (message.subtype == RouterWire::SUBTYPE_PRESENCE) {
        this->answerPresence(message.sender);
    }
    this->spreadNewMessage(message, receivedFrom);
}

// A verified routed Router message (Group 0xFE, UNICAST). An answer (ACK, ROUTE_REPORT) teaches the way to its signer on
// every hop (D6, signed by the node it leads to — D5); the destination acts on it, relays forward it like any UNICAST —
// a route probe with this relay added.
void Router::acceptVerifiedRouterMessage(RoutedMessage message, const PeerId& receivedFrom) {
    const bool isAnswer = message.subtype == RouterWire::SUBTYPE_ACK || message.subtype == RouterWire::SUBTYPE_ROUTE_REPORT || message.subtype == RouterWire::SUBTYPE_PRESENCE_REPLY;
    if (message.destination == this->selfIdentity->getPeerId()) {
        if (message.subtype == RouterWire::SUBTYPE_ACK)          this->receiveAckForUs(message, receivedFrom);
        if (message.subtype == RouterWire::SUBTYPE_ROUTE_REPORT) this->receiveRouteReportForUs(message, receivedFrom);
        if (message.subtype == RouterWire::SUBTYPE_RECORD_ROUTE) this->sendRouteReport(message, receivedFrom);
        if (message.subtype == RouterWire::SUBTYPE_ROUTE_ERROR)  this->receiveRouteErrorForUs(message);
        if (message.subtype == RouterWire::SUBTYPE_PRESENCE_REPLY) this->learnRoute(message.sender, receivedFrom, hopsTraveled(message), RouteEvidence::Broadcast);
        return;                                                                     // unknown subtype: nothing
    }
    // Only the addressee measured a round trip; for a relay the answer proves just that its signer reaches the addressee
    // over us — broadcast-grade evidence, or a relay replaying ACKs would look confirmed (review R-5 I2, D5)
    if (isAnswer) this->learnRoute(message.sender, receivedFrom, hopsTraveled(message), RouteEvidence::Broadcast);
    if (message.mode == RoutingMode::Routed) {                                      // e.g. a ROUTE_REPORT on the reversed route
        this->relayRouted(std::move(message), receivedFrom);
        return;
    }
    if (message.ttlRemaining <= 1) return;
    message.ttlRemaining -= 1;
    if (message.subtype == RouterWire::SUBTYPE_RECORD_ROUTE) {
        RecordRoutePayload probe;
        RouterWire::decodeRecordRoutePayload(message.payload, probe);              // shape checked by decode
        if (probe.hops.size() < 255) {                                              // full: forwarded without us
            probe.hops.push_back({ this->selfIdentity->getPeerId(), offsetSince(probe.sentAtUnixMs) });
            message.payload = RouterWire::encodeRecordRoutePayload(probe);          // per-hop part, outside the signature
        }
    }
    this->forwardUnicast(message, receivedFrom);
}

void Router::receiveAckForUs(const RoutedMessage& ack, const PeerId& receivedFrom) {
    AckPayload payload;
    RouterWire::decodeAckPayload(ack.payload, payload);                            // shape checked by decode
    const auto rtt = this->acceptAnswer(payload.acknowledgedMsgId, ack.sender);
    // A round trip we asked for confirms the route; an unsolicited ACK teaches it like a broadcast
    this->learnRoute(ack.sender, receivedFrom, hopsTraveled(ack), rtt ? RouteEvidence::Ack : RouteEvidence::Broadcast, rtt);
    if (!rtt) return;                                                               // not asked for, not from the addressee, a repeat or too late

    const AckReceipt receipt{ payload.acknowledgedMsgId, ack.sender, *rtt, hopsTraveled(ack) };
    this->notifyListeners([&](RouterEventListener& listener) { listener.onAckReceived(receipt); }, "onAckReceived");
}

void Router::receiveRouteReportForUs(const RoutedMessage& report, const PeerId& receivedFrom) {
    RouteReportPayload payload;
    RouterWire::decodeRouteReportPayload(report.payload, payload);                 // shape checked by decode
    const auto rtt = this->acceptAnswer(payload.probeMsgId, report.sender);
    this->learnRoute(report.sender, receivedFrom, hopsTraveled(report), rtt ? RouteEvidence::Ack : RouteEvidence::Broadcast, rtt);   // a round trip that worked, like an ACK
    if (!rtt) return;                                                               // not our probe, not from the probed node, a repeat or too late
    const RouteReport event{ report.sender, payload.probeMsgId, std::move(payload.hops), payload.receivedOffsetMs, *rtt };
    this->notifyListeners([&](RouterEventListener& listener) { listener.onRouteReported(event); }, "onRouteReported");
}

// The sender of an unsigned UNICAST is not authenticated (until C2): a forged one must not make us sign an ACK and flood
// it toward anyone (review R-5 I4). So an ACK goes only to a neighbor or over a route we learned from the sender's own
// signed messages — never by local flooding — and one neighbor gets at most unicastAcksPerNeighborPerSecond of them.
bool Router::mayAcknowledgeUnsigned(const PeerId& sender, const PeerId& receivedFrom) {
    // A neighbor that already left gets no budget entry: it would never be erased (review R-6 M1)
    if (!this->isNeighbor(receivedFrom) || !this->knowsWayTo(sender)) return false;

    const auto now = std::chrono::steady_clock::now();
    auto& [windowStart, acknowledged] = this->unicastAcksByNeighbor[receivedFrom];
    if (now - windowStart >= std::chrono::seconds(1)) { windowStart = now; acknowledged = 0; }
    if (acknowledged >= this->config.unicastAcksPerNeighborPerSecond) return false;
    ++acknowledged;
    return true;
}

bool Router::isNeighbor(const PeerId& node) const {
    std::lock_guard lock(this->neighborsMutex);
    return this->neighbors.contains(node);
}

// A neighbor, or a node we have a learned route to — what we may answer without local flooding
bool Router::knowsWayTo(const PeerId& node) const {
    if (this->isNeighbor(node)) return true;
    std::lock_guard lock(this->routesMutex);
    return !this->routes.nextHops(node).empty();
}

// An addressee answers ACK_REQUESTED: a signed UNICAST back to the sender (docs/router.md 3.3)
void Router::sendAck(const RoutedMessage& acknowledged) {
    ++this->acksSent;
    this->sendOwnRouterMessage(this->buildRouterMessage(acknowledged.sender, RouterWire::SUBTYPE_ACK, RouterWire::encodeAckPayload({ acknowledged.msgId })));
}

// The probe's destination signs what reached it and answers along the reversed recorded route (ROUTED) — arriving proves
// the route both ways. The record is outside the probe's signature, so it is used only when its last relay is the
// neighbor that really handed us the probe and it is walkable; otherwise the report goes back as UNICAST.
void Router::sendRouteReport(const RoutedMessage& probe, const PeerId& receivedFrom) {
    RecordRoutePayload recorded;
    RouterWire::decodeRecordRoutePayload(probe.payload, recorded);
    std::vector<PeerId> reversed;
    for (auto hop = recorded.hops.rbegin(); hop != recorded.hops.rend(); ++hop) reversed.push_back(hop->node);
    const PeerId& handedOverBy = recorded.hops.empty() ? probe.sender : recorded.hops.back().node;
    const bool reversible = handedOverBy == receivedFrom && isUsableSourceRoute(reversed, this->selfIdentity->getPeerId(), probe.sender);

    const RouteReportPayload report{ probe.msgId, recorded.sentAtUnixMs, offsetSince(recorded.sentAtUnixMs), std::move(recorded.hops) };
    this->sendOwnRouterMessage(this->buildRouterMessage(probe.sender, RouterWire::SUBTYPE_ROUTE_REPORT, RouterWire::encodeRouteReportPayload(report),
                                                        reversible ? std::optional(std::move(reversed)) : std::nullopt));
}

// ROUTE_ERROR for a ROUTED message of ours: the reporting relay could not hand it on
void Router::receiveRouteErrorForUs(const RoutedMessage& error) {
    RouteErrorPayload payload;
    RouterWire::decodeRouteErrorPayload(error.payload, payload);                   // shape checked by decode
    this->concludeRouteFailure(payload.stuckMsgId, error.sender, payload.unreachableDestination, payload.reason);
}

// One failure per message, and only from a relay of its route (or this node, when the first hop failed): anyone else
// could otherwise make us drop good routes. The route learned through the failed route's first hop goes too.
void Router::concludeRouteFailure(uint64_t msgId, const PeerId& reportedBy, const PeerId& unreachableHop, RouteErrorReason reason) {
    const auto awaited = this->awaitedReplies.find(msgId);
    if (awaited == this->awaitedReplies.end() || !awaited->second.routeRelays || !awaited->second.addressee) return;
    const std::vector<PeerId> relays = std::move(*awaited->second.routeRelays);
    awaited->second.routeRelays.reset();
    if (reportedBy != this->selfIdentity->getPeerId() && std::find(relays.begin(), relays.end(), reportedBy) == relays.end()) {
        awaited->second.routeRelays = relays;                                       // not a relay of this route: ignored, still waiting
        return;
    }

    const PeerId destination = *awaited->second.addressee;
    if (reason != RouteErrorReason::NextHopSendRefused) {
        // A refused send (full queue, message too large) says nothing about the route — only a missing link does (review R-6 I1)
        std::lock_guard lock(this->routesMutex);
        this->routes.forgetRoute(destination, relays.empty() ? destination : relays.front());
    }
    const RouteFailure failure{ destination, msgId, reportedBy, unreachableHop, reason };
    this->notifyListeners([&](RouterEventListener& listener) { listener.onRouteFailed(failure); }, "onRouteFailed");
}

// A relay that cannot hand a ROUTED message on tells its sender. The sender of unsigned data is not authenticated, so —
// like an ACK (review R-5 I4) — the error goes only over a known way, and one neighbor's messages cause at most one per
// routeErrorInterval: forged ROUTED frames must not turn us into a source of signed traffic toward anyone.
void Router::sendRouteError(const RoutedMessage& stuck, const PeerId& receivedFrom, const PeerId& unreachableHop, RouteErrorReason reason) {
    if (!this->isNeighbor(receivedFrom) || !this->knowsWayTo(stuck.sender)) return;  // a departed neighbor's entry would never be erased
    const auto now = std::chrono::steady_clock::now();
    auto& lastReport = this->routeErrorReportedAt[receivedFrom];
    if (lastReport && now - *lastReport < this->config.routeErrorInterval) return;
    lastReport = now;
    ++this->routeErrorsSent;
    this->sendOwnRouterMessage(this->buildRouterMessage(stuck.sender, RouterWire::SUBTYPE_ROUTE_ERROR, RouterWire::encodeRouteErrorPayload({ stuck.msgId, unreachableHop, reason })));
}

// Signed UNICAST of the Router's own (Group 0xFE); safe on any thread — signing needs only the identity
RoutedMessage Router::buildRouterMessage(const PeerId& destination, uint16_t subtype, std::vector<uint8_t> payload, std::optional<std::vector<PeerId>> relays) const {
    RoutedMessage message;
    message.group             = RouterWire::ROUTER_PROTOCOL_GROUP;
    message.subtype           = subtype;
    message.mode              = relays ? RoutingMode::Routed : RoutingMode::Unicast;
    message.ttlInitial        = static_cast<uint8_t>(std::max<size_t>(this->config.unicastTtl, relays ? relays->size() + 1 : 0));
    message.ttlRemaining      = message.ttlInitial;
    if (relays) message.sourceRoute = SourceRoute{ 0, std::move(*relays) };
    message.msgId             = randomMessageId();
    message.sentAtUnixSeconds = currentUnixSeconds();
    message.sender            = this->selfIdentity->getPeerId();
    message.destination       = destination;
    message.payload           = std::move(payload);
    message.signature         = this->selfIdentity->sign(RouterWire::bytesToSign(message));
    return message;
}

void Router::sendOwnRouterMessage(const RoutedMessage& message) {
    this->rememberSeen(message);
    if (message.mode == RoutingMode::Routed) this->forwardRouted(message, std::nullopt);
    else                                     this->forwardUnicast(message, std::nullopt);
}

// Routes end only with their neighbor (no expiry). Until the Dispatch thread goes (C6) a message may be processed after
// its neighbor's disconnect — it must not bring a route through that neighbor back (review R-5 I1). The Router thread is
// the only writer of both sets, so the check cannot go stale before the insert.
void Router::learnRoute(const PeerId& destination, const PeerId& via, uint8_t hops, RouteEvidence evidence, std::optional<std::chrono::milliseconds> rtt) {
    {
        std::lock_guard lock(this->neighborsMutex);
        if (!this->neighbors.contains(via)) return;
    }
    std::lock_guard lock(this->routesMutex);
    this->routes.learn(destination, via, hops, evidence, std::chrono::steady_clock::now(), rtt);
}

void Router::awaitReply(uint64_t msgId, const std::optional<PeerId>& addressee, bool acceptsAnswers, std::optional<std::vector<PeerId>> routeRelays) {
    const auto now = std::chrono::steady_clock::now();
    this->dropExpiredAwaitedReplies(now);
    if (this->awaitedReplyOrder.size() >= this->config.maxAwaitedReplies && !this->awaitedReplyOrder.empty()) {
        this->awaitedReplies.erase(this->awaitedReplyOrder.front().second);
        this->awaitedReplyOrder.pop_front();
    }
    this->awaitedReplies[msgId] = AwaitedReply{ now, addressee, acceptsAnswers, std::move(routeRelays), {} };
    this->awaitedReplyOrder.emplace_back(now, msgId);
}

// Time since we sent `awaitedMsgId` when `answerer` may answer it: we asked, the wait window is open, the answerer is
// the addressee (anyone for a broadcast — every node is one) and has not answered yet. Kept until the window ends: a
// broadcast collects one ACK from every node. Answers are signed by the answerer, so a relay cannot answer for another.
std::optional<std::chrono::milliseconds> Router::acceptAnswer(uint64_t awaitedMsgId, const PeerId& answerer) {
    const auto awaited = this->awaitedReplies.find(awaitedMsgId);
    if (awaited == this->awaitedReplies.end()) return std::nullopt;
    AwaitedReply& reply = awaited->second;
    if (!reply.acceptsAnswers || (reply.addressee && *reply.addressee != answerer)) return std::nullopt;
    if (!reply.answeredBy.insert(answerer).second) return std::nullopt;
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - reply.sentAt);
}

void Router::dropExpiredAwaitedReplies(std::chrono::steady_clock::time_point now) {
    while (!this->awaitedReplyOrder.empty() && now - this->awaitedReplyOrder.front().first >= this->config.replyWaitWindow) {
        this->awaitedReplies.erase(this->awaitedReplyOrder.front().second);
        this->awaitedReplyOrder.pop_front();
    }
}

// A BROADCAST copy we already have: the link it came by is redundant (PRUNE) — unless the copy has a higher TTL than ours.
// That is a better path; and when ours could not be forwarded at all (TTL ran out here, e.g. a relay set it to 1 to win
// the race), the better TTL goes on now. The content comes from our verified copy — only the unsigned TTL is taken
// from the duplicate, so an unverified copy cannot smuggle anything in.
void Router::reactToBroadcastDuplicate(const RoutedMessage& message, const PeerId& receivedFrom) {
    const RoutedMessageKey key{ message.sender, message.msgId };
    const RoutedMessage* held = this->broadcastCache.find(key);
    // The duplicate is unverified, its ttlInitial included: a TTL above what an honest neighbor can send (our copy's
    // ttlInitial, so ttlInitial − 1 after our hop) is capped, or a forged frame could leave us a copy nobody can encode
    const int offeredTtl = held ? std::min(message.ttlRemaining - 1, held->ttlInitial - 1) : -1;
    const bool higherTtl = held && offeredTtl > held->ttlRemaining;
    if (this->plumtree.onDuplicate(receivedFrom, higherTtl)) {
        if (this->network.sendToPeer(receivedFrom, RouterWire::encodePrune()) > 0) ++this->prunesSent;
    }
    if (!higherTtl || held->ttlRemaining > 0) return;

    RoutedMessage better = *held;
    better.ttlRemaining = static_cast<uint8_t>(offeredTtl);
    if (this->broadcastCache.replace(better, std::chrono::steady_clock::now())) this->broadcastCache.markSentTo(key, receivedFrom);
    this->spreadByPlumtree(better, receivedFrom, true);
}

// Remembered, or possibly forgotten early because the duplicate memory overflowed — either way it must not count as new
bool Router::isAlreadySeen(const RoutedMessage& message) const {
    const SeenMessageCache& seen = RouterWire::requiresSignature(message.group, message.mode) ? this->seenMessages : this->unsignedSeenMessages;
    return seen.contains({ message.sender, message.msgId }) || seen.predatesEvictedKeys(message.sentAtUnixSeconds);
}

// Unsigned messages (UNICAST data, D12) cost nothing to forge, so they get their own memory: a flood of them cannot push
// out signed keys nor raise the floor signed messages are judged by. Their sentAt is capped at our clock — a forged
// future time would otherwise keep the floor up, and unsigned traffic silenced, for the whole clock skew (review R-5 C1).
void Router::rememberSeen(const RoutedMessage& message) {
    const auto now = std::chrono::steady_clock::now();
    if (RouterWire::requiresSignature(message.group, message.mode)) this->seenMessages.remember({ message.sender, message.msgId }, message.sentAtUnixSeconds, now);
    else this->unsignedSeenMessages.remember({ message.sender, message.msgId }, std::min(message.sentAtUnixSeconds, currentUnixSeconds()), now);
}

void Router::sendOwnBroadcast(const RoutedMessage& message) {
    this->rememberSeen(message);                                                    // echoes are dropped
    this->spreadNewMessage(message, std::nullopt);
}

// A verified message seen for the first time — ours (`receivedFrom` empty, sent as built) or a neighbor's (TTL − 1).
// docs/router.md 4.3: never back to where it came from, never to its originator; TTL ending here means no copies and
// no announcements.
void Router::spreadNewMessage(const RoutedMessage& message, const std::optional<PeerId>& receivedFrom) {
    RoutedMessage outgoing = message;
    const bool forwarding = !receivedFrom || message.ttlRemaining > 1;              // the next hop would receive TTL 0
    if (receivedFrom && message.ttlRemaining > 0) outgoing.ttlRemaining -= 1;

    if (message.mode == RoutingMode::Broadcast) {
        // Also when not forwarded: a better TTL may still come (4.3). The neighbor it came from has it.
        if (this->broadcastCache.store(outgoing, std::chrono::steady_clock::now()) && receivedFrom) this->broadcastCache.markSentTo({ outgoing.sender, outgoing.msgId }, *receivedFrom);
        this->spreadByPlumtree(outgoing, receivedFrom, forwarding);
        return;
    }

    // FLOOD: a full copy to every other neighbor
    if (!forwarding) return;
    const std::vector<uint8_t> frame = RouterWire::encode(outgoing);
    if (frame.empty()) return;
    for (const PeerId& neighbor : this->neighborsSnapshot()) {
        if (neighbor == receivedFrom || neighbor == message.sender) continue;
        this->sendFullCopy(neighbor, frame);
    }
}

void Router::spreadByPlumtree(const RoutedMessage& outgoing, const std::optional<PeerId>& receivedFrom, bool forwarding) {
    const RoutedMessageKey key{ outgoing.sender, outgoing.msgId };
    const PlumtreeNewMessageDecision decision = this->plumtree.onNewMessage(key, receivedFrom, forwarding, std::chrono::steady_clock::now());
    if (decision.graftTo) this->sendGraft(*decision.graftTo, {});
    if (decision.pruneTo && this->network.sendToPeer(*decision.pruneTo, RouterWire::encodePrune()) > 0) ++this->prunesSent;
    if (decision.fullCopyTo.empty()) return;

    const std::vector<uint8_t> frame = RouterWire::encode(outgoing);
    if (frame.empty()) return;
    for (const PeerId& neighbor : decision.fullCopyTo) {
        if (this->sendFullCopy(neighbor, frame)) this->broadcastCache.markSentTo(key, neighbor);   // a later GRAFT from it gets nothing twice
    }
}

bool Router::sendFullCopy(const PeerId& neighbor, const std::vector<uint8_t>& frame) {
    if (this->network.sendToPeer(neighbor, frame) <= 0) return false;
    ++this->fullMessagesSent;
    return true;
}

// docs/router.md 4.2. Not signed (D12), so "seen" is recorded at once — and nothing is learned from it (D5: only
// messages signed by the destination teach routes).
void Router::handleIncomingUnicast(RoutedMessage message, const PeerId& receivedFrom) {
    if (message.sender == this->selfIdentity->getPeerId() || this->isAlreadySeen(message)) {   // local flooding brings copies
        ++this->duplicatesDropped;
        return;
    }
    this->rememberSeen(message);

    if (message.destination == this->selfIdentity->getPeerId()) {
        this->deliverLocally(message, message.sender == receivedFrom);               // the link proves only a direct neighbor
        if (message.ackRequested && this->mayAcknowledgeUnsigned(message.sender, receivedFrom)) this->sendAck(message);
        return;
    }
    if (message.ttlRemaining <= 1) return;                                          // the next hop would receive TTL 0
    message.ttlRemaining -= 1;
    this->forwardUnicast(message, receivedFrom);
}

// docs/router.md 4.2, unsigned ROUTED data: like UNICAST — seen at once, nothing learned — but the route is the sender's
void Router::handleIncomingRouted(RoutedMessage message, const PeerId& receivedFrom) {
    if (message.sender == this->selfIdentity->getPeerId() || this->isAlreadySeen(message)) {
        ++this->duplicatesDropped;
        return;
    }
    this->rememberSeen(message);
    if (message.destination == this->selfIdentity->getPeerId()) {
        this->deliverLocally(message, message.sender == receivedFrom);
        if (message.ackRequested && this->mayAcknowledgeUnsigned(message.sender, receivedFrom)) this->sendAck(message);
        return;
    }
    this->relayRouted(std::move(message), receivedFrom);
}

// This node is the named relay: step the route on and hand the message to the next hop
void Router::relayRouted(RoutedMessage message, const PeerId& receivedFrom) {
    if (message.ttlRemaining <= 1) return;                                          // the sender gives enough TTL for its route
    message.ttlRemaining -= 1;
    message.sourceRoute->nextHopIndex += 1;
    this->forwardRouted(message, receivedFrom);
}

// To the hop the route names next — no other choice: the sender asked for this route. A next hop that is not a neighbor,
// or refuses the send, ends the message here; the sender hears of it (ROUTE_ERROR, or directly when it is us).
void Router::forwardRouted(const RoutedMessage& outgoing, const std::optional<PeerId>& receivedFrom) {
    const PeerId& nextHop = nextRoutedHop(outgoing);
    bool isNeighbor;
    {
        std::lock_guard lock(this->neighborsMutex);
        isNeighbor = this->neighbors.contains(nextHop);
    }
    const std::vector<uint8_t> frame = RouterWire::encode(outgoing);
    std::optional<RouteErrorReason> failure;
    if (!isNeighbor)                                                failure = RouteErrorReason::NextHopNotNeighbor;
    else if (frame.empty() || !this->sendFullCopy(nextHop, frame)) failure = RouteErrorReason::NextHopSendRefused;

    if (!failure) {
        if (receivedFrom) ++this->routedForwarded;
        return;
    }
    if (outgoing.sender == this->selfIdentity->getPeerId()) this->concludeRouteFailure(outgoing.msgId, outgoing.sender, nextHop, *failure);
    else if (receivedFrom)                                  this->sendRouteError(outgoing, *receivedFrom, nextHop, *failure);
}

// The next hop for one node: the destination itself when it is a neighbor, else the learned routes in order (the first
// that accepts the send), else every neighbor but the one it came from — local flooding, bounded by TTL and duplicates
void Router::forwardUnicast(const RoutedMessage& outgoing, const std::optional<PeerId>& receivedFrom) {
    const std::vector<uint8_t> frame = RouterWire::encode(outgoing);
    if (frame.empty()) return;
    const PeerId& destination = *outgoing.destination;
    const std::vector<PeerId> neighbors = this->neighborsSnapshot();

    if (std::find(neighbors.begin(), neighbors.end(), destination) != neighbors.end() && this->sendFullCopy(destination, frame)) return;

    std::vector<PeerId> nextHops;
    {
        std::lock_guard lock(this->routesMutex);
        nextHops = this->routes.nextHops(destination, receivedFrom);
    }
    for (const PeerId& nextHop : nextHops) {
        if (nextHop != outgoing.sender && this->sendFullCopy(nextHop, frame)) return;
    }

    ++this->localFloods;
    for (const PeerId& neighbor : neighbors) {
        if (neighbor != receivedFrom && neighbor != outgoing.sender) this->sendFullCopy(neighbor, frame);
    }
}

void Router::deliverLocally(const RoutedMessage& message, bool senderAuthenticated) {
    RoutedDelivery delivery;
    delivery.sender       = message.sender;
    delivery.msgId        = message.msgId;
    delivery.group        = message.group;
    delivery.subtype      = message.subtype;
    delivery.mode         = message.mode;
    delivery.hopsTraveled = hopsTraveled(message);
    delivery.senderAuthenticated = senderAuthenticated;
    delivery.payload      = message.payload;
    this->notifyListeners([&](RouterEventListener& listener) { listener.onMessageDelivered(delivery); }, "onMessageDelivered");
}

// Snapshot under the lock, call without it (a listener may add or remove listeners); one failing listener does not stop the rest
void Router::notifyListeners(const std::function<void(RouterEventListener&)>& call, const char* event) {
    std::vector<std::shared_ptr<RouterEventListener>> snapshot;
    {
        std::shared_lock lock(this->listenersMutex);
        snapshot = this->listeners;
    }
    for (const auto& listener : snapshot) {
        try {
            call(*listener);
        } catch (const std::exception& e) {
            this->log.format(LogLevel::Error, "listener->{} threw: {}", event, e.what());
        } catch (...) {
            this->log.format(LogLevel::Error, "listener->{} threw unknown exception", event);
        }
    }
}

} // namespace invilite::Mesh
