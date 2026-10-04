#pragma once

#ifndef MESH_NETWORK_H
#define MESH_NETWORK_H

#include "meshlink/peer.h"
#include "meshlink/identity.h"
#include "meshlink/peer_directory.h"
#include "meshlink/network_events.h"
#include "meshlink/pex_announce.h"
#include "meshlink/topology_planner.h"
#include "meshlink/signed_peer_record.h"
#include "meshlink/thread_safe_queue.h"
#include "transport/TcpServer.h"

#include <array>
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

    struct NetworkConfig {
        uint16_t                    listenPort        = 0;
        std::string                 listenAddress     = "::";
        std::string                 nodeName          = "";

        // Addresses we announce to other peers via selfRecord.
        // These should be reachable endpoints where others can connect back to us.
        // On MVP the user fills this manually; future: auto-discovery via STUN-like protocol.
        std::vector<PeerAddress>    announcedAddresses;

        uint8_t                     targetOutbound    = 8;
        uint8_t                     maxInbound        = 16;
        uint8_t                     maxTotal          = 32;
        int                         backlog           = 16;

        // PEX_ANNOUNCE — number of verified peers to share on each new connection right after HELLO.
        // Actual batch may be smaller if our verified pool is smaller.
        uint8_t                     initialPexBatchSize = 5;

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
                NetworkConfig config = {});
        ~Network();

        Network(const Network&)            = delete;
        Network& operator=(const Network&) = delete;

        void start();
        void stop();

        // Schedule an outbound connection to the given address. Worker thread performs TCP connect,
        // transport handshake, identity verification, and finally adds the peer to the active peer pool.
        // Returns immediately — actual connection attempt runs asynchronously.
        void connectToPeer(const std::string& address, uint16_t port);

        // ── Event subscription ──────────────────────────────────────────────────────────────
        // Register a listener for connection lifecycle and message events. Network keeps the
        // listener alive via shared_ptr until removeListener or destruction. Safe to call
        // before or after start(). See NetworkEventListener for the threading contract.
        void addListener(std::shared_ptr<NetworkEventListener> listener);
        void removeListener(const std::shared_ptr<NetworkEventListener>& listener);

        ssize_t sendToPeer(const PeerId& dest, const std::vector<uint8_t>& data);
        size_t  sendToAllConnected(const std::vector<uint8_t>& data);

        std::vector<PeerId>             getConnectedPeers() const;
        size_t                          getConnectedPeerCount() const;

        // Returns snapshot of known peers (learned via HELLO or PEX_ANNOUNCE).
        // Convenience wrapper over peerDirectory — equivalent to projecting `record` from each KnownPeer.
        std::vector<SignedPeerRecord>   getKnownPeers() const;

    private:
        struct Command {
            enum class Type { AddPeer };
            Type                    type;
            std::shared_ptr<Peer>   peer;
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
        void sendHelloTo(const std::shared_ptr<Peer>& peer);                            // send our selfRecord to given peer
        void processGoodbyeMessage(const ProtocolMessage& msg);                         // subtype 0x0040
        void sendGoodbyeTo(const std::shared_ptr<Peer>& peer, GoodbyeReason reason);
        // Single path for every frame sent to a peer. Wakes the I/O thread when part of the frame stayed queued, so it
        // starts polling POLLOUT now instead of after the poll timeout.
        ssize_t sendFrameTo(const std::shared_ptr<Peer>& peer, const std::vector<uint8_t>& frame) const;

        // Send a one-shot PEX_ANNOUNCE with a random sample of verifiedReachable peers.
        // Called from managementLoop right after sendHelloTo — same trigger (peer became Active).
        void sendInitialPexTo(const std::shared_ptr<Peer>& peer);

        // Periodic anti-entropy tick — picks the N least-recently-announced verified records
        // and broadcasts them to all connected peers.
        void tickPeriodicPex();

        // Pick a uniformly random interval in [periodicPexMinInterval, periodicPexMaxInterval].
        // Falls back to min if max <= min (misconfigured).
        std::chrono::seconds pickRandomPexInterval();

        // Called when a peer transitions to Active (handleWakeup/AddPeer).
        // Enqueues a HELLO send request into commandQueue (or calls from Management after dequeuing via a sidechannel).
        // We use a dedicated queue so HELLO sends happen off the I/O thread.
        void scheduleHelloSend(std::shared_ptr<Peer> peer);

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
        void onIncomingConnection(int fd, const sockaddr_storage* addr);
        void runIncomingHandshake(int fd, sockaddr_storage addr, HandshakeWorker* self);
        void runOutgoingHandshake(std::string address, uint16_t port, HandshakeWorker* self);
        void joinFinishedHandshakeWorkers();

        // ===== Helpers =====
        void wakeupIoThread() const;
        void markAllPeersForClose();
        void finalCleanupAllPeers();

        // ===== PEX =====
        void processPexAnnounceMessage(const ProtocolMessage& msg);                     // subtype 0x0020

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
        void runProbeWorker(PeerId expected, std::string address, uint16_t port, HandshakeWorker* self);

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

        // ===== Self-attested record about us, signed by selfIdentity =====
        // Built in start(), sent to new peers via HELLO.
        std::vector<uint8_t>                             selfRecordSerialized;          // pre-serialized for fast send

        // ===== Lifecycle state =====
        std::atomic<bool>                                running{false};
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

        // ===== Inter-thread queues =====
        ThreadSafeQueue<Command>                         commandQueue;                  // workers → I/O
        ThreadSafeQueue<ProtocolMessage>                 messageProtocolQueue;          // I/O → Management (0xFF protocol)
        ThreadSafeQueue<NetworkMessage>                  routerMessageQueue;            // I/O → Dispatch (router/application layer)
        ThreadSafeQueue<std::shared_ptr<Peer>>           helloSendQueue;                // I/O → Management (send HELLO to this peer)

        // ===== Event listeners =====
        // Subscribers for connection lifecycle and message events. Listed under shared_mutex —
        // many concurrent reads (per-event iteration) and rare writes (add/remove).
        mutable std::shared_mutex                                       listenersMutex;
        std::vector<std::shared_ptr<NetworkEventListener>>              listeners;

        // ===== Connected peers — I/O thread is the ONLY writer =====
        mutable std::shared_mutex                                       peersMutex;
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