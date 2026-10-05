#pragma once

#ifndef MESH_ROUTER_H
#define MESH_ROUTER_H

#include "meshlink/broadcast_cache.h"
#include "meshlink/identity.h"
#include "meshlink/peer_directory.h"
#include "meshlink/plumtree_state.h"
#include "meshlink/router_events.h"
#include "meshlink/router_wire.h"
#include "meshlink/seen_message_cache.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <array>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace invilite::Mesh {

    class Network;
    struct NetworkMessage;

    // Router parameters (docs/router.md 5, initial values)
    struct RouterConfig {
        uint8_t                     broadcastTtl            = 16;                   // hops a broadcast may travel; 1 = direct neighbors only
        std::chrono::seconds        maxClockSkew            = std::chrono::minutes(5);    // accepted sentAt distance from local time
        std::chrono::seconds        duplicateWindow         = std::chrono::minutes(10);   // > 2 × maxClockSkew: a replay is remembered or too old
        size_t                      duplicateCacheCapacity  = 65536;
        std::chrono::milliseconds   unknownSenderWait       = std::chrono::seconds(2);    // how long a message waits for its sender's record
        size_t                      pendingVerificationLimit = 256;                 // messages waiting for a sender's record, all senders together
        size_t                      pendingVerificationPerNeighbor = 32;            // share of one neighbor — it cannot starve the others
        std::chrono::seconds        unknownModeReportInterval = std::chrono::seconds(60);   // at most one UNKNOWN_DELIVERY_MODE per neighbor and mode
        PlumtreeConfig              plumtree;                                       // BROADCAST mode (docs/router.md 4.3)
        std::chrono::seconds        graftCacheRetention     = std::chrono::seconds(30);   // how long a BROADCAST can be served on GRAFT
        size_t                      graftCacheByteLimit     = 8 * 1024 * 1024;
    };

    // Counters for tests and measurements (docs/router.md 6: full sends per broadcast). Monotonic since construction.
    struct RouterStatistics {
        uint64_t    fullMessagesSent   = 0;                                         // routed frames handed to Network: own, forwarded, GRAFT answers
        uint64_t    duplicatesDropped  = 0;                                         // already-seen messages received again, our own included
        uint64_t    announcementsSent  = 0;                                         // message keys announced in IHAVE
        uint64_t    graftsSent         = 0;                                         // GRAFT frames, fast-repair ones included
        uint64_t    prunesSent         = 0;
    };

    // Router (docs/router.md): delivers messages beyond direct neighbors — broadcast to every node, or to one node by
    // per-hop decisions, source route or flood. Sits on top of Network: receives through a NetworkEventListener and sends
    // with Network::sendToPeer. Network knows nothing about the Router beyond the reserved Group 0xFE.
    //
    // Threading: one Router thread owns all routing state. Network's threads and application threads only push events into
    // the Router's queue and return — the Router never runs on, and never blocks, a Network thread. The Router thread itself
    // is shared by every peer, so it must never block either (sends are non-blocking since B7).
    //
    // Lifetime: stop() before the Network is destroyed; Network keeps only the queue-owning listener alive, so a late
    // event after stop() lands in a queue nobody drains instead of touching a destroyed Router.
    class Router {
    public:
        // PeerDirectory supplies the senders' public keys; LocalIdentity signs this node's messages.
        Router(Network& network, std::shared_ptr<PeerDirectory> peerDirectory, std::shared_ptr<LocalIdentity> selfIdentity, RouterConfig config = {});
        ~Router();

        Router(const Router&)            = delete;
        Router& operator=(const Router&) = delete;

        // Registers with Network and starts the Router thread. Peers already connected become neighbors right away.
        void start();
        void stop();

        // Send to every node. Signed here, on the caller's thread; sent by the Router thread. Returns the message id, or
        // nothing when the Router is not running, `group` is not a user group (0x00..0xFD) or `mode` does not reach every
        // node. Not delivered locally. The mode is signed and applies on every hop: Flood trades traffic for no tree-repair
        // delay (docs/router.md 4.3).
        std::optional<uint64_t> broadcast(uint8_t group, uint16_t subtype, std::vector<uint8_t> payload, RoutingMode mode = RoutingMode::Broadcast);

        void addListener(std::shared_ptr<RouterEventListener> listener);
        void removeListener(const std::shared_ptr<RouterEventListener>& listener);

        // Directly connected peers as the Router sees them (its own view, updated from Network events)
        std::vector<PeerId> getNeighbors() const;

        RouterStatistics getStatistics() const;

    private:
        class EventInbox;                                                           // NetworkEventListener → Router queue
        struct Event;

        // A broadcast whose sender's record we do not have yet; waits for the PEX_REQUEST answer (docs/router.md 4.1)
        struct PendingVerification {
            RoutedMessage                           message;
            PeerId                                  receivedFrom{};
            std::chrono::steady_clock::time_point   deadline;
        };

        void routerLoop();
        void processEvent(Event& event);
        void handleRouterControl(const NetworkMessage& message);                   // Group 0xFE neighbor-only subtypes
        void handleRoutedMessage(const NetworkMessage& message);                   // routing header: Group 0x00..0xFD, routed Group 0xFE subtypes
        void reportUnknownMode(const RoutedMessage& message, const PeerId& receivedFrom);
        void handleIncomingBroadcast(RoutedMessage message, const PeerId& receivedFrom);
        void awaitSenderRecord(RoutedMessage message, const PeerId& receivedFrom);
        void retryPendingVerifications();
        [[nodiscard]] bool isAlreadySeen(const RoutedMessage& message) const;
        void acceptBroadcastWithKey(RoutedMessage message, const PeerId& receivedFrom, std::span<const uint8_t> senderEd25519Pub);
        void reactToBroadcastDuplicate(const RoutedMessage& message, const PeerId& receivedFrom);
        void sendOwnBroadcast(const RoutedMessage& message);
        void spreadNewMessage(const RoutedMessage& message, const std::optional<PeerId>& receivedFrom);
        void spreadByPlumtree(const RoutedMessage& outgoing, const std::optional<PeerId>& receivedFrom, bool forwarding);
        void sendFullCopy(const PeerId& neighbor, const std::vector<uint8_t>& frame);
        void handleAnnouncement(const PeerId& from, std::span<const uint8_t> payload);
        void handleGraft(const PeerId& from, std::span<const uint8_t> payload);
        void sendGraft(const PeerId& neighbor, const std::vector<RoutedMessageKey>& keys);
        void sendAnnouncements(const PeerId& neighbor, const std::vector<RoutedMessageKey>& keys);
        void runPlumtreeTimers(std::chrono::steady_clock::time_point now);
        [[nodiscard]] bool isWaitingForVerification(const RoutedMessageKey& key) const;
        void deliverLocally(const RoutedMessage& message);
        [[nodiscard]] std::vector<PeerId> neighborsSnapshot() const;

        Network&                                    network;
        std::shared_ptr<PeerDirectory>              peerDirectory;
        std::shared_ptr<LocalIdentity>              selfIdentity;
        const RouterConfig                          config;

        std::shared_ptr<EventInbox>                 inbox;
        std::thread                                 routerThread;
        std::atomic<bool>                           running{false};

        // Router thread only
        SeenMessageCache                            seenMessages;
        PlumtreeState                               plumtree;
        BroadcastCache                              broadcastCache;                 // BROADCAST copies as we forward them, for GRAFT answers
        std::vector<PendingVerification>            pendingVerifications;
        std::chrono::steady_clock::time_point       nextPendingRetryAt{};
        // Last UNKNOWN_DELIVERY_MODE sent per neighbor, indexed by the mode nibble; forgotten when the neighbor leaves
        std::unordered_map<PeerId, std::array<std::optional<std::chrono::steady_clock::time_point>, 16>, PeerIDHash> unknownModeReportedAt;

        // Written by the Router thread (and by start() before the thread runs); read by getNeighbors()
        mutable std::mutex                          neighborsMutex;
        std::unordered_set<PeerId, PeerIDHash>      neighbors;

        std::atomic<uint64_t>                       fullMessagesSent{0};
        std::atomic<uint64_t>                       duplicatesDropped{0};
        std::atomic<uint64_t>                       announcementsSent{0};
        std::atomic<uint64_t>                       graftsSent{0};
        std::atomic<uint64_t>                       prunesSent{0};

        mutable std::shared_mutex                   listenersMutex;
        std::vector<std::shared_ptr<RouterEventListener>> listeners;
    };

} // namespace invilite::Mesh

#endif // MESH_ROUTER_H
