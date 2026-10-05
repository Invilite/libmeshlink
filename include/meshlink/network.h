#pragma once

#ifndef MESH_NETWORK_H
#define MESH_NETWORK_H

#include "meshlink/peer.h"
#include "meshlink/identity.h"
#include "meshlink/observed_address.h"
#include "meshlink/peer_directory.h"
#include "meshlink/network_events.h"
#include "meshlink/pex_announce.h"
#include "meshlink/topology_planner.h"
#include "meshlink/signed_peer_record.h"
#include "meshlink/thread_safe_queue.h"
#include "meshlink/connection_slots.h"
#include "meshlink/log.h"
#include "transport/TcpServer.h"

#include <array>
#include <optional>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace invilite::Mesh {

    class Connection;

    // Connection limits (roadmap R10). Soft = target, may be exceeded briefly. Hard = never exceeded.
    // A hard limit left empty is derived from its soft limit — no "magic zero".
    struct ConnectionLimits {
        // Healthy number of established connections in both directions — a target, not a limit.
        uint16_t total = 24;

        struct Inbound {
            uint16_t                soft = 16;                                          // accepted normally up to here; above → dismissed with GOODBYE(NoSlots)
            std::optional<uint16_t> hard;                                               // above → closed right after accept(), nothing allocated; default 2 × soft
            uint16_t                perAddress = 5;                                     // inbound connections (handshakes + established) from one IP
            [[nodiscard]] uint16_t effectiveHard() const { return this->hard.value_or(static_cast<uint16_t>(2 * this->soft)); }
        } inbound;

        struct Outbound {
            uint16_t                min  = 2;                                           // kept even when inbound is full — we pick these ourselves (eclipse protection)
            uint16_t                soft = 12;                                          // upper bound of Topology's target
            std::optional<uint16_t> hard;                                               // never exceeded, probes included; default soft + 3
            [[nodiscard]] uint16_t effectiveHard() const { return this->hard.value_or(static_cast<uint16_t>(this->soft + 3)); }
        } outbound;
    };

    struct NetworkConfig {
        uint16_t                    listenPort        = 0;
        std::string                 listenAddress     = "::";
        std::string                 nodeName          = "";

        // Addresses we announce to other peers via selfRecord.
        // These should be reachable endpoints where others can connect back to us.
        // On MVP the user fills this manually; future: auto-discovery via STUN-like protocol.
        std::vector<PeerAddress>    announcedAddresses;

        ConnectionLimits            connectionLimits;
        int                         backlog           = 16;

        // PEX_ANNOUNCE — number of verified peers to share on each new connection right after HELLO.
        // Actual batch may be smaller if our verified pool is smaller.
        uint8_t                     initialPexBatchSize = 5;

        // Address book bound (R2): identities are free to mint, so gossip must not grow the book without limit. When full,
        // a new record replaces the least valuable entry or is dropped — see chooseEvictionVictim.
        size_t                      maxKnownPeers       = 500;

        // Periodic anti-entropy PEX tick — slow systematic gossip to fill gaps left by flood + initial exchange.
        // At each tick, a random interval in [min, max] is picked; up to batchSize verified records with the
        // oldest lastAnnouncedAt are broadcast to all connected peers.
        uint8_t                     periodicPexBatchSize    = 3;
        std::chrono::seconds        periodicPexMinInterval  = std::chrono::seconds(20);
        std::chrono::seconds        periodicPexMaxInterval  = std::chrono::seconds(120);

        // Per-connection send queue: encrypted frames the kernel could not take yet. Bounds the memory one slow reader can
        // hold; once full, sends to that peer fail with SendQueueFull. Also the largest message that can be sent.
        // Minimum 64 KB (validated in the Network constructor).
        size_t                      sendQueueLimitBytes     = Connection::defaultSendQueueLimit;
        // A peer whose queued frames made no progress for this long has stopped reading — its connection is closed.
        std::chrono::seconds        sendStallTimeout        = std::chrono::seconds(15);

        // After this many consecutive failed dials an Available peer becomes Unavailable and is handed to the probe,
        // which keeps checking it with its own backoff. Topology stops wasting dials on a peer that is gone.
        uint8_t                     connectionFailuresBeforeUnavailable = 3;

        // Probe backoff and connection attempt backoff are tracked per-peer in KnownPeer
        // (consecutiveProbeFailures + nextProbeAllowedAt, consecutiveConnectionFailures + nextConnectionAttemptAt).
        // The schedule is shared between both — see computeBackoffInterval() in network.cpp.
    };

// Internal management-protocol message (group 0xFF) consumed by the Management thread.
    struct ProtocolMessage {
        std::shared_ptr<Peer>   peer;
        uint16_t                subtype = 0;
        std::vector<uint8_t>    payload;
        // Fact supplied by the connection layer: the remote IP we dialed when this connection is outbound, empty when
        // the peer dialed us. Discovery uses it as reachability evidence without reaching into Peer/Connection (A1 M2).
        std::string             dialedAddress;
        // The same for the other direction: the remote IP the peer connected to us from when it dialed us, empty when
        // we dialed it. Discovery uses it to tell a peer behind NAT (public source, private announced addresses).
        std::string             connectedFromAddress;
    };

// Reason codes sent in a GOODBYE frame before closing a connection.
    enum class GoodbyeReason : uint8_t {
        Shutdown     = 0x00,  // clean node shutdown
        NoSlots      = 0x01,  // no inbound slots available (speed dating)
        FoundAnother = 0x02,  // replacing this connection with a better candidate
    };

// Scheduled PEX_ANNOUNCE broadcast — drained one-per-second by the management thread.
// We store PeerId (not the full record), so the drain always reads the latest version from
// the PeerDirectory — if a newer record arrived in the meantime, we propagate the fresher one.
    struct PendingPexBroadcast {
        PeerId recordPeerId;
        PeerId excludePeerId;                                                           // source — we never send back to where we learned it from
    };

    class Network {
    public:
        // PeerDirectory is injected so other components (Router, MessageCrypto, NetworkMap)
        // can share the same source of truth about known peers.
        Network(std::shared_ptr<LocalIdentity> selfIdentity,
                std::shared_ptr<std::array<uint8_t, 64>> networkSecret,
                std::shared_ptr<PeerDirectory> peerDirectory,
                NetworkConfig config = {},
                std::shared_ptr<Logger> logger = {});                                   // null → default Logger (stderr, Info)
        ~Network();

        Network(const Network&)            = delete;
        Network& operator=(const Network&) = delete;

        void start();
        void stop();

        // Schedule an outbound connection to the given address. Worker thread performs TCP connect,
        // transport handshake, identity verification, and finally adds the peer to the active peer pool.
        // Returns immediately — actual connection attempt runs asynchronously.
        void connectToPeer(const std::string& address, uint16_t port);

        // The Logger this Network writes to — the Router defaults to the same one
        [[nodiscard]] const std::shared_ptr<Logger>& getLogger() const { return this->log.getLogger(); }

        // ── Event subscription ──────────────────────────────────────────────────────────────
        // Register a listener for connection lifecycle and message events. Network keeps the
        // listener alive via shared_ptr until removeListener or destruction. Safe to call
        // before or after start(). See NetworkEventListener for the threading contract.
        void addListener(std::shared_ptr<NetworkEventListener> listener);
        void removeListener(const std::shared_ptr<NetworkEventListener>& listener);

        // Send a complete frame (Group | Subtype | payload) to a connected peer. Group 0xFF belongs to Network alone and is
        // refused (-1), as is a frame shorter than the 3-byte header. Group 0xFE (Router control) is reserved for the Router
        // by convention; the API moves to the Router in C6. Never blocks — see Network::sendFrameTo.
        ssize_t sendToPeer(const PeerId& dest, const std::vector<uint8_t>& data);
        size_t  sendToAllConnected(const std::vector<uint8_t>& data);                   // same refusals; returns 0

        // Discovery service for the Router: ask a connected neighbor for the records of `wanted` peers (PEX_REQUEST,
        // at most PexAnnounceCodec::MAX_RECORDS_PER_BATCH ids). The answer arrives as an ordinary PEX_ANNOUNCE and lands
        // in PeerDirectory like any gossip. False when the neighbor is not connected, the list is empty or too long,
        // or the send was refused.
        bool    requestPeerRecords(const PeerId& neighbor, const std::vector<PeerId>& wanted);

        std::vector<PeerId>             getConnectedPeers() const;

        // How peers we dialed see us (OBSERVED_ADDRESS), newest last, at most 8 distinct addresses. A public one we do
        // not announce means this node is behind NAT — reachable from outside only with port forwarding.
        std::vector<ObservedSelfAddress> getObservedSelfAddresses() const;
        size_t                          getConnectedPeerCount() const;

        // Returns snapshot of known peers (learned via HELLO or PEX_ANNOUNCE).
        // Convenience wrapper over peerDirectory — equivalent to projecting `record` from each KnownPeer.
        std::vector<SignedPeerRecord>   getKnownPeers() const;

    private:
        struct Command {
            enum class Type { AddPeer };
            Type                                    type = Type::AddPeer;
            std::shared_ptr<Peer>                   peer;
            std::optional<ConnectionSlots::Slot>    slot;                               // resources the connection holds — kept until it closes (R10)
        };

        // Connection-layer fact handed to the management thread (I/O → Management). Replaces the old "send HELLO"
        // queue (A1 S3): the I/O thread reports what happened, the management thread decides what to send.
        struct PeerLifecycleEvent {
            enum class Type { Activated, Dismissed };
            Type                    type = Type::Activated;
            std::shared_ptr<Peer>   peer;
            GoodbyeReason           reason = GoodbyeReason::Shutdown;                   // Dismissed only
            std::string             connectedFromAddress;                               // Activated, inbound only: the IP it dialed us from (a fact from I/O)
        };

        // Initial PEX for one peer, built by discovery; the caller sends it and then marks the records as announced.
        struct InitialPexBatch {
            std::vector<uint8_t>    frame;
            std::vector<PeerId>     recordIds;
        };

        struct HandshakeWorker {
            std::thread             thread;
            std::atomic<bool>       done{false};
        };

        // Result of an outbound connection attempt up to and including identity verification.
        // On Success, `connection` and `remoteIdentity` are populated; on any other result only
        // `verification` is meaningful and the caller should not touch the other fields.
        struct OutboundConnectionResult {
            VerificationResult           verification = VerificationResult::ConnectionError;
            std::shared_ptr<Connection>  connection;
            PeerIdentity                 remoteIdentity;
            IdentityFlags                remoteFlags;
        };

        // Perform TCP connect + transport handshake + identity verification as initiator.
        // Shared between connectToPeer (flagsSelf={}) and probePeer (flagsSelf.probe=true).
        // On any failure step the partially-constructed Connection is closed before returning.
        OutboundConnectionResult establishOutboundConnection(const std::string& address, uint16_t port, IdentityFlags flagsSelf) const;

        // ===== Thread loops =====
        void ioLoop();
        void managementLoop();
        void dispatchLoop();

        // ===== I/O thread internals =====
        void handleWakeup();
        // Reads and dispatches frames from one peer within a per-round budget (R5). Returns true when the budget ran out
        // with complete frames still in the Connection's buffer — the I/O loop must come back without a poll() event.
        bool handleConnectionReadable(int fd, short revents);
        void handleConnectionWritable(int fd);                                          // POLLOUT — flush the peer's send queue
        void cleanClosedPeers();
        void parseAndDispatchFrame(const std::shared_ptr<Peer>& peer, std::vector<uint8_t> message);

        // ===== Management thread internals =====
        void dispatchProtocolMessage(const ProtocolMessage& msg);
        std::chrono::milliseconds tickTopology();  // evaluate topology and act on the decision

        // ===== 0xFF protocol handlers =====
        void processHelloMessage(const ProtocolMessage& msg);                           // subtype 0x0001
        void processGoodbyeMessage(const ProtocolMessage& msg);                         // subtype 0x0040
        void processObservedAddressMessage(const ProtocolMessage& msg);                 // subtype 0x0002

        // ===== Discovery content (who we are, whom we know) — sent by whoever owns the moment =====
        [[nodiscard]] std::vector<uint8_t> buildHelloFrame() const;                    // empty if selfRecord is missing
        [[nodiscard]] std::optional<InitialPexBatch> buildInitialPexFor(const PeerId& target) const;
        void markRecordsAnnounced(const std::vector<PeerId>& recordIds);

        // Discovery's greeting for a peer that became Active: HELLO + initial PEX.
        void greetActivatedPeer(const std::shared_ptr<Peer>& peer, const std::string& connectedFromAddress);

        // Departure window (B3), connection-layer side: the peer is already Departing. Sends the farewell (HELLO + PEX
        // when dismissing with NoSlots, so the dismissed peer still learns where else to go), then GOODBYE, then
        // half-closes once flushed. The remote closes; the I/O thread enforces DEPARTURE_TIMEOUT.
        void sendFarewellAndDepart(const std::shared_ptr<Peer>& peer, GoodbyeReason reason);

        // Dial-side reaction to GOODBYE(NoSlots): the peer is reachable but full — growing backoff on its own counter,
        // so it is never mistaken for failed dials (B8 would demote it). Availability is not touched.
        void recordNoSlotsRejection(const PeerId& peerId);
        // An outbound connection that stayed Active past OUTBOUND_SETTLED_AFTER was accepted for good — the peer's
        // NoSlots rejection count starts over. (Not on HELLO: HELLO always precedes a GOODBYE(NoSlots).)
        void forgetNoSlotsRejectionsOfSettledPeers();
        void sendGoodbyeTo(const std::shared_ptr<Peer>& peer, GoodbyeReason reason);     // farewell path — peer must be Departing
        // Single path for every frame sent to a peer. Wakes the I/O thread when part of the frame stayed queued, so it
        // starts polling POLLOUT now instead of after the poll timeout.
        ssize_t sendFrameTo(const std::shared_ptr<Peer>& peer, const std::vector<uint8_t>& frame) const;


        // Periodic anti-entropy tick — picks the N least-recently-announced verified records
        // and broadcasts them to all connected peers.
        void tickPeriodicPex();

        // Pick a uniformly random interval in [periodicPexMinInterval, periodicPexMaxInterval].
        // Falls back to min if max <= min (misconfigured).
        std::chrono::seconds pickRandomPexInterval();


        // ===== Listener notification =====
        // Snapshot the listener vector under shared lock, then iterate without the lock so a
        // listener that calls back into addListener/removeListener can't deadlock. Per-listener
        // exceptions are caught and logged so one bad listener doesn't poison the others.
        void notifyPeerConnected(const PeerIdentity& identity);
        void notifyPeerDisconnected(const PeerId& peerId);
        void notifyMessageReceived(const NetworkMessage& msg);

        // ===== Peer lifecycle =====
        bool shouldReplaceExistingPeer(const Peer& existing, const Peer& candidate) const;

        // ===== Handshake workers =====
        // Accept thread (TcpServer): admission against the inbound hard and per-address limits (R10/R1) before
        // anything is allocated for the connection.
        void onIncomingConnection(int fd, const sockaddr_storage* addr);
        void runIncomingHandshake(int fd, sockaddr_storage addr, ConnectionSlots::Slot slot, HandshakeWorker* self);
        // Dials the addresses in order until one answers with a verified identity (F4)
        void dialAddresses(std::vector<PeerAddress> addresses);
        void runOutgoingHandshake(std::vector<PeerAddress> addresses, ConnectionSlots::Slot slot, HandshakeWorker* self);
        void joinFinishedHandshakeWorkers();
        void joinFinishedProbeWorkers();                                                // discovery's own workers (A1 S1)

        // ===== Helpers =====
        void wakeupIoThread() const;
        void markAllPeersForClose();
        void finalCleanupAllPeers();
        // Peers visible as connected — Active only. Joining / Departing / Closing peers are invisible above this layer.
        [[nodiscard]] std::vector<std::shared_ptr<Peer>> activePeersSnapshot() const;

        // ===== PEX =====
        void processPexAnnounceMessage(const ProtocolMessage& msg);                     // subtype 0x0020
        void processPexRequestMessage(const ProtocolMessage& msg);                      // subtype 0x0021

        // Common insert/update path for HELLO and PEX_ANNOUNCE. Returns true iff the caller
        // should enqueue a PEX broadcast for this record — true only when the record is new,
        // updated to a newer version, or just gained hasEverConnected, AND hasEverConnected
        // is currently true.
        bool upsertKnownPeer(SignedPeerRecord&& record, bool outboundMatch);

        // Enqueue a PEX broadcast. Actual send is throttled by managementLoop's 1-per-second drain.
        void enqueuePexBroadcast(const PeerId& recordPeerId, const PeerId& excludePeerId);

        // Called once per second by managementLoop. Pops at most one pending broadcast, fetches
        // the current record from peerDirectory, and sends it to all connected peers except the source.
        void sendPendingPexBroadcasts();

        // ===== Probe =====
        // Run a peer probe — internally checks whether a probe can/should be run now (no probe
        // currently in flight, at least one candidate available with elapsed nextProbeAllowedAt)
        // and launches a probe worker if all conditions are met. If nothing to do, returns silently.
        void runPeerProbe();

        // Probe worker body. Establishes an outbound connection with the probe flag set,
        // verifies that the remote PeerId matches `expected`, and commits the result to
        // peerDirectory. Always closes the connection before returning.
        void runProbeWorker(PeerId expected, std::vector<PeerAddress> addresses, ConnectionSlots::Slot slot, HandshakeWorker* self);

        // Commit a probe's result. Only updates state if still Probing — guards against races
        // where a newer record arrived during the probe and reset the state.
        // On success also enqueues a PEX broadcast. Caller is management or probe worker thread.
        void commitProbeResult(const PeerId& expected, bool success);

        // Record an outbound connection attempt failure for the given peer. Increments the failure
        // counter and schedules nextConnectionAttemptAt according to the shared backoff schedule.
        // Called by runOutgoingHandshake when establishOutboundConnection fails.
        // No-op if peer is not in peerDirectory (e.g. connectToPeer to a bootstrap address before HELLO).
        void recordConnectionAttemptFailure(const std::string& address, uint16_t port);

        // Discovery's reaction to repeated failed dials reported by the connection layer: availability belongs to
        // discovery, so the connection layer only reports the count. Demotes Available → Unavailable at the threshold.
        void demoteAfterRepeatedDialFailures(const PeerId& peerId, uint8_t consecutiveFailures);

        // ===== Configuration (immutable after construction) =====
        std::shared_ptr<LocalIdentity>                  selfIdentity;
        std::shared_ptr<std::array<uint8_t, 64>>        networkSecret;
        NetworkConfig                                   config;
        ComponentLog                                    log;

        // Bound logs a remote peer can trigger (malformed frames, protocol violations); one limiter per thread, no locks
        LogRateLimiter                                  ioThreadLogLimiter;
        LogRateLimiter                                  managementThreadLogLimiter;
        LogRateLimiter                                  listenerThreadLogLimiter;

        // ===== Self-attested record about us, signed by selfIdentity =====
        // Built in start(), sent to new peers via HELLO.
        std::vector<uint8_t>                             selfRecordSerialized;          // pre-serialized for fast send

        // ===== Lifecycle state =====
        std::atomic<bool>                                running{false};
        std::atomic<bool>                                stopping{false};               // stop() in its departure window: no new connections, no listener events
        std::mutex                                       stopMutex;                     // a concurrent stop() (e.g. ~Network) waits for the running one
        Transport::Platform::WakeupSignal                ioWakeup;                       // wakes the I/O thread out of its poll

        // ===== Transport =====
        std::unique_ptr<Transport::TcpServer>            tcpServer;

        // ===== Threads =====
        std::thread                                      ioThread;
        std::thread                                      managementThread;
        std::thread                                      dispatchThread;

        // ===== Handshake workers =====
        std::mutex                                       handshakeWorkersMutex;
        std::vector<std::unique_ptr<HandshakeWorker>>    handshakeWorkers;
        bool                                             acceptingHandshakeWorkers = false;   // under handshakeWorkersMutex — false once stop() collects them

        // ===== Probe workers — discovery's own, touched only by the management thread (and stop() after it joined) =====
        std::vector<std::unique_ptr<HandshakeWorker>>    probeWorkers;

        // ===== Hard connection limits (R10) =====
        ConnectionSlots                                  connectionSlots;
        std::unordered_map<const Peer*, ConnectionSlots::Slot> peerSlots;               // I/O thread only: slots of registered peers, released on reap

        // ===== Inter-thread queues =====
        ThreadSafeQueue<Command>                         commandQueue;                  // workers → I/O
        ThreadSafeQueue<ProtocolMessage>                 messageProtocolQueue;          // I/O → Management (0xFF protocol)
        ThreadSafeQueue<NetworkMessage>                  routerMessageQueue;            // I/O → Dispatch (router/application layer)
        ThreadSafeQueue<PeerLifecycleEvent>              peerLifecycleEvents;           // I/O → Management (peer activated / dismissed)

        // ===== Event listeners =====
        // Subscribers for connection lifecycle and message events. Listed under shared_mutex —
        // many concurrent reads (per-event iteration) and rare writes (add/remove).
        mutable std::shared_mutex                                       listenersMutex;
        std::vector<std::shared_ptr<NetworkEventListener>>              listeners;

        // ===== Connected peers — I/O thread is the ONLY writer =====
        mutable std::shared_mutex                                       peersMutex;

        // Discovery: how peers we dialed see us (management thread writes, getObservedSelfAddresses reads)
        mutable std::mutex                                              observedSelfMutex;
        std::vector<ObservedSelfAddress>                                observedSelfAddresses;
        std::unordered_map<PeerId, std::shared_ptr<Peer>, PeerIDHash>   peersById;
        std::unordered_map<int,    std::shared_ptr<Peer>>               peersBySocket;

        // ===== Known peers — externally owned, internally thread-safe =====
        // Shared with Router/MessageCrypto/NetworkMap (future) so all components see the same set.
        // No mutex at this level — PeerDirectory locks per-operation internally.
        std::shared_ptr<PeerDirectory>                                  peerDirectory;

        // ===== PEX broadcast queue =====
        ThreadSafeQueue<PendingPexBroadcast>                            pexBroadcastQueue;

        // ===== Peer probe state =====
        // Single probe in flight at a time — prevents flooding when many peers need probing.
        // Per-peer cooldowns live in KnownPeer::nextProbeAllowedAt.
        std::atomic<bool>                         probeInFlight{false};

        TopologyPlanner topologyPlanner;
    };

} // namespace invilite::Mesh

#endif // MESH_NETWORK_H