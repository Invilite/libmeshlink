#include "meshlink/network.h"
#include "meshlink/identity.h"
#include "meshlink/thread_signals.h"
#include "transport/TcpClient.h"

#include <poll.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <random>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace invilite::Mesh {

    namespace {
        constexpr int    POLL_TIMEOUT_MS          = 100;
        constexpr size_t MIN_SEND_QUEUE_LIMIT     = 64 * 1024;                     // Fits the largest 0xFF message (PEX batch of MAX_RECORDS_PER_BATCH records) with room to spare
        constexpr size_t WAKEUP_DRAIN_BUFFER      = 64;
        constexpr int    OUTBOUND_CONNECT_TIMEOUT = 5;
        // Upper bound of one outbound attempt: TCP connect (5 s) + transport handshake (3 s) + identity verification
        // (2 × 3 s receive) + registration, with margin. Topology does not redial a peer within this window (R9).
        constexpr std::chrono::seconds OUTBOUND_ATTEMPT_MAX_DURATION{20};
        constexpr size_t FRAME_HEADER_SIZE        = 3;                                  // group(1) + subtype(2)
        constexpr uint8_t GROUP_INTERNAL          = 0xFF;

        // Management protocol subtypes
        constexpr uint16_t SUBTYPE_HELLO          = 0x0001;
        constexpr uint16_t SUBTYPE_PEX_ANNOUNCE   = 0x0020;
        constexpr uint16_t SUBTYPE_GOODBYE        = 0x0040;

        // Shared backoff schedule for both probe and connection attempt retries.
        // Index = consecutive failure count (clamped to last entry). Caps at 20 minutes — past that
        // we are not learning anything new by retrying faster, and offline peers shouldn't generate
        // constant traffic. Array index 0 is used after the FIRST failure (1 failure → 10s wait).
        constexpr std::chrono::seconds BACKOFF_SCHEDULE[] = {
        std::chrono::seconds(10),
        std::chrono::seconds(30),
        std::chrono::seconds(60),
        std::chrono::seconds(120),
        std::chrono::seconds(300),
        std::chrono::seconds(600),
        std::chrono::seconds(1200),
    };
    constexpr size_t BACKOFF_SCHEDULE_LEN = sizeof(BACKOFF_SCHEDULE) / sizeof(BACKOFF_SCHEDULE[0]);

    // Map a failure count to a wait duration. failureCount of 0 means "never failed" — caller
    // shouldn't be calling us in that case, but defensively returns the first interval.
    std::chrono::seconds computeBackoffInterval(uint8_t failureCount) {
    if (failureCount == 0) return BACKOFF_SCHEDULE[0];
    const size_t idx = std::min<size_t>(failureCount - 1, BACKOFF_SCHEDULE_LEN - 1);
    return BACKOFF_SCHEDULE[idx];
}

std::string peerIdShort(const PeerId& id) {
    char buf[13];
    std::snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x%02x", id[0], id[1], id[2], id[3], id[4], id[5]);
    return std::string(buf);
}

// Build a complete frame: [group:1][subtype:2 BE][payload:n]
std::vector<uint8_t> buildFrame(uint8_t group, uint16_t subtype, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> out;
    out.reserve(FRAME_HEADER_SIZE + payload.size());
    out.push_back(group);
    out.push_back(static_cast<uint8_t>((subtype >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(subtype & 0xFF));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

// Order-insensitive comparison — a peer may list the same endpoints in a different order after re-signing.
bool hasSameAddressSet(const std::vector<PeerAddress>& a, const std::vector<PeerAddress>& b) {
    return a.size() == b.size() && std::is_permutation(a.begin(), a.end(), b.begin());
}

// Reachability evidence: we dialed this peer and reached it at an IP its own record announces.
bool recordAnnouncesDialedAddress(const SignedPeerRecord& record, const std::string& dialedAddress) {
    if (dialedAddress.empty()) return false;                                        // inbound connection — no evidence about its addresses
    return std::any_of(record.addresses.begin(), record.addresses.end(), [&](const PeerAddress& a) { return a.address == dialedAddress; });
}
}

// ============================================================
// Construction / destruction
// ============================================================

Network::Network(std::shared_ptr<LocalIdentity> selfIdentity,
                 std::shared_ptr<std::array<uint8_t, 64>> networkSecret,
                 std::shared_ptr<PeerDirectory> peerDirectory,
                 NetworkConfig config)
        : selfIdentity(std::move(selfIdentity))
        , networkSecret(std::move(networkSecret))
        , config(std::move(config))
        , peerDirectory(std::move(peerDirectory)) {

    if (!this->selfIdentity)  throw std::invalid_argument("Network requires a valid LocalIdentity");
    if (!this->networkSecret) throw std::invalid_argument("Network requires a valid network secret");
    if (!this->peerDirectory) throw std::invalid_argument("Network requires a valid PeerDirectory");

    if (this->config.sendQueueLimitBytes < MIN_SEND_QUEUE_LIMIT) {
        throw std::invalid_argument("sendQueueLimitBytes is below the minimum needed for management messages");
    }
    if (this->config.maxTotal < this->config.targetOutbound) {
        throw std::invalid_argument("maxTotal cannot be less than targetOutbound");
    }
}

Network::~Network() {
    if (this->running.load()) {
        this->stop();
    }
}

void Network::start() {
    if (this->running.exchange(true)) return;

    // Build self-attested record — needed before any peer connects.
    // LocalIdentity owns the signing logic; we cache the serialized bytes here for fast HELLO sends.
    {
        const SignedPeerRecord rec = this->selfIdentity->buildSelfRecord(this->config.announcedAddresses);
        this->selfRecordSerialized = SignedPeerRecordCodec::serialize(rec);
        if (this->selfRecordSerialized.empty()) {
            this->running.store(false);
            throw std::runtime_error("Failed to serialize selfRecord");
        }
        std::cerr << "Network: built selfRecord for " << peerIdShort(rec.peerId)
                  << " with " << rec.addresses.size() << " announced address(es), size="
                  << this->selfRecordSerialized.size() << "B" << std::endl;
    }

    if (::pipe(this->wakeupPipe) == -1) {
        this->running.store(false);
        throw std::runtime_error("Failed to create wakeup pipe");
    }

    for (const int fd : { this->wakeupPipe[0], this->wakeupPipe[1] }) {
        const int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags == -1 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
            ::close(this->wakeupPipe[0]);
            ::close(this->wakeupPipe[1]);
            this->wakeupPipe[0] = this->wakeupPipe[1] = -1;
            this->running.store(false);
            throw std::runtime_error("Failed to set wakeup pipe non-blocking");
        }
    }

    if (this->config.listenPort != 0) {
        this->tcpServer = std::make_unique<Transport::TcpServer>(this->config.listenPort);
        this->tcpServer->onConnect([this](int fd, const sockaddr_storage* addr) {
            this->onIncomingConnection(fd, addr);
        });

        if (this->tcpServer->start() != 0) {
            this->tcpServer.reset();
            ::close(this->wakeupPipe[0]);
            ::close(this->wakeupPipe[1]);
            this->wakeupPipe[0] = this->wakeupPipe[1] = -1;
            this->running.store(false);
            throw std::runtime_error("Failed to start TcpServer");
        }
    }

    this->dispatchThread = std::thread(&Network::dispatchLoop, this);
    pthread_setname_np(this->dispatchThread.native_handle(), "EventDispatcher");

    this->managementThread = std::thread(&Network::managementLoop, this);
    pthread_setname_np(this->managementThread.native_handle(), "PeerManager");

    this->ioThread = std::thread(&Network::ioLoop, this);
    pthread_setname_np(this->ioThread.native_handle(), "TransportLoop");
}

void Network::stop() {
    if (!this->running.exchange(false)) return;

    if (this->tcpServer) {
        this->tcpServer->stop();
    }

    // Send GOODBYE to all active peers before closing — allows remote side to react gracefully.
    {
        std::shared_lock lock(this->peersMutex);
        for (const auto& [id, peer] : this->peersById) {
            if (peer->isActive()) this->sendGoodbyeTo(peer, GoodbyeReason::Shutdown);
        }
    }

    this->markAllPeersForClose();
    this->wakeupIoThread();

    if (this->ioThread.joinable()) this->ioThread.join();

    // Now wake Management and Dispatch — I/O no longer produces messages
    this->messageProtocolQueue.shutdown();
    this->routerMessageQueue.shutdown();
    this->helloSendQueue.shutdown();

    if (this->managementThread.joinable()) this->managementThread.join();
    if (this->dispatchThread.joinable())   this->dispatchThread.join();

    {
        std::lock_guard lock(this->handshakeWorkersMutex);
        for (auto& w : this->handshakeWorkers) {
            if (w->thread.joinable()) w->thread.join();
        }
        this->handshakeWorkers.clear();
    }

    Command cmd;
    while (this->commandQueue.tryPop(cmd)) {
        if (cmd.peer) cmd.peer->closeConnection();
    }

    this->finalCleanupAllPeers();
    this->tcpServer.reset();

    if (this->wakeupPipe[0] != -1) ::close(this->wakeupPipe[0]);
    if (this->wakeupPipe[1] != -1) ::close(this->wakeupPipe[1]);
    this->wakeupPipe[0] = this->wakeupPipe[1] = -1;
}

// ============================================================
// Public API
// ============================================================

void Network::connectToPeer(const std::string& address, uint16_t port) {
    if (!this->running.load()) return;

    auto  worker    = std::make_unique<HandshakeWorker>();
    auto* workerPtr = worker.get();

    worker->thread = std::thread([this, address, port, workerPtr]() {
        this->runOutgoingHandshake(address, port, workerPtr);
    });

    {
        std::lock_guard lock(this->handshakeWorkersMutex);
        this->handshakeWorkers.push_back(std::move(worker));
    }
}

void Network::addListener(std::shared_ptr<NetworkEventListener> listener) {
    if (!listener) return;
    std::unique_lock lock(this->listenersMutex);
    this->listeners.push_back(std::move(listener));
}

void Network::removeListener(const std::shared_ptr<NetworkEventListener>& listener) {
    if (!listener) return;
    std::unique_lock lock(this->listenersMutex);
    this->listeners.erase(
            std::remove(this->listeners.begin(), this->listeners.end(), listener),
            this->listeners.end()
    );
}

ssize_t Network::sendToPeer(const PeerId& dest, const std::vector<uint8_t>& data) {
    std::shared_ptr<Peer> peer;
    {
        std::shared_lock lock(this->peersMutex);
        const auto it = this->peersById.find(dest);
        if (it == this->peersById.end()) return -1;
        peer = it->second;
    }
    return this->sendFrameTo(peer, data);
}

size_t Network::sendToAllConnected(const std::vector<uint8_t>& data) {
    std::vector<std::shared_ptr<Peer>> snapshot;
    {
        std::shared_lock lock(this->peersMutex);
        snapshot.reserve(this->peersById.size());
        for (const auto& [id, peer] : this->peersById) snapshot.push_back(peer);
    }

    size_t successCount = 0;
    for (auto& peer : snapshot) {
        if (this->sendFrameTo(peer, data) > 0) ++successCount;
    }
    return successCount;
}

std::vector<PeerId> Network::getConnectedPeers() const {
    std::shared_lock lock(this->peersMutex);
    std::vector<PeerId> result;
    result.reserve(this->peersById.size());
    for (const auto& [id, _] : this->peersById) result.push_back(id);
    return result;
}

size_t Network::getConnectedPeerCount() const {
    std::shared_lock lock(this->peersMutex);
    return this->peersById.size();
}

std::vector<SignedPeerRecord> Network::getKnownPeers() const {
    const auto entries = this->peerDirectory->listPeers();
    std::vector<SignedPeerRecord> result;
    result.reserve(entries.size());
    for (const auto& kp : entries) result.push_back(kp.record);
    return result;
}

// ============================================================
// Listener notification
// ============================================================

void Network::notifyPeerConnected(const PeerIdentity& identity) {
    // Snapshot listener vector under shared lock — release before invoking, so a listener
    // that calls back into add/removeListener can't deadlock. shared_ptr copies bump refcounts
    // so listeners stay alive even if removed mid-iteration.
    std::vector<std::shared_ptr<NetworkEventListener>> snapshot;
    {
        std::shared_lock lock(this->listenersMutex);
        snapshot = this->listeners;
    }

    for (const auto& l : snapshot) {
        try {
            l->onPeerConnected(identity);
        } catch (const std::exception& e) {
            std::cerr << "Network: listener->onPeerConnected threw: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "Network: listener->onPeerConnected threw unknown exception" << std::endl;
        }
    }
}

void Network::notifyPeerDisconnected(const PeerId& peerId) {
    std::vector<std::shared_ptr<NetworkEventListener>> snapshot;
    {
        std::shared_lock lock(this->listenersMutex);
        snapshot = this->listeners;
    }

    for (const auto& l : snapshot) {
        try {
            l->onPeerDisconnected(peerId);
        } catch (const std::exception& e) {
            std::cerr << "Network: listener->onPeerDisconnected threw: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "Network: listener->onPeerDisconnected threw unknown exception" << std::endl;
        }
    }
}

void Network::notifyMessageReceived(const NetworkMessage& msg) {
    std::vector<std::shared_ptr<NetworkEventListener>> snapshot;
    {
        std::shared_lock lock(this->listenersMutex);
        snapshot = this->listeners;
    }

    for (const auto& l : snapshot) {
        try {
            l->onMessageReceived(msg);
        } catch (const std::exception& e) {
            std::cerr << "Network: listener->onMessageReceived threw: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "Network: listener->onMessageReceived threw unknown exception" << std::endl;
        }
    }
}

// ============================================================
// Handshake workers
// ============================================================

void Network::onIncomingConnection(int fd, const sockaddr_storage* addr) {
    if (!this->running.load()) {
        ::close(fd);
        return;
    }

    sockaddr_storage addrCopy{};
    if (addr) addrCopy = *addr;

    auto  worker    = std::make_unique<HandshakeWorker>();
    auto* workerPtr = worker.get();

    worker->thread = std::thread([this, fd, addrCopy, workerPtr]() {
        this->runIncomingHandshake(fd, addrCopy, workerPtr);
    });

    {
        std::lock_guard lock(this->handshakeWorkersMutex);
        this->handshakeWorkers.push_back(std::move(worker));
    }
}

void Network::runIncomingHandshake(int fd, sockaddr_storage addr, HandshakeWorker* self) {
    blockSigpipeInCurrentThread();

    std::shared_ptr<Connection> conn;
    try {
        conn = std::make_shared<Connection>(fd, &addr, this->networkSecret.get(), this->config.sendQueueLimitBytes);
    } catch (const std::exception& e) {
        std::cerr << "Network: incoming Connection construction failed: " << e.what() << std::endl;
        ::close(fd);
        self->done.store(true, std::memory_order_release);
        return;
    }

    const int hs = conn->waitForHandshake();
    if (hs < 0) {
        std::cerr << "Network: incoming handshake failed, code=" << hs << std::endl;
        conn->close();
        self->done.store(true, std::memory_order_release);
        return;
    }

    PeerIdentity remoteIdentity;
    IdentityFlags remoteFlags;                                                          // 6.1: receive peer intent (probe vs normal)
    const VerificationResult vr = IdentityVerification::runAsResponder(
            *conn, *this->selfIdentity, this->config.nodeName, remoteIdentity, remoteFlags
    );

    if (vr != VerificationResult::Success) {
        std::cerr << "Network: incoming identity verification failed, result="
                  << static_cast<int>(vr) << " fd=" << fd << std::endl;
        conn->close();
        self->done.store(true, std::memory_order_release);
        return;
    }

    // If the initiator declared this is a probe, they want to validate our reachability
    // without joining our peer pool. We respond by closing — they've already verified us
    // through the IdentityVerification handshake itself.
    if (remoteFlags.probe()) {
        std::cerr << "Network: incoming probe from " << peerIdShort(remoteIdentity.getPeerId())
                  << " — identity verified, closing connection" << std::endl;
        conn->close();
        self->done.store(true, std::memory_order_release);
        return;
    }

    auto peer = std::make_shared<Peer>(std::move(conn), std::move(remoteIdentity), false);

    Command cmd;
    cmd.type = Command::Type::AddPeer;
    cmd.peer = std::move(peer);
    this->commandQueue.push(std::move(cmd));
    this->wakeupIoThread();

    self->done.store(true, std::memory_order_release);
}

// ============================================================
// Outbound connection establishment — shared by normal connect and probe
// ============================================================

Network::OutboundConnectionResult Network::establishOutboundConnection(const std::string& address, const uint16_t port, const IdentityFlags flagsSelf) const {
    OutboundConnectionResult result;

    // ── TCP connect ───────────────────────────────────────────────────────────
    Transport::TcpClient client;
    sockaddr_storage     remoteAddr{};

    client.onConnect([&remoteAddr](int /*socket*/, const sockaddr_storage* addr) {
        if (addr) remoteAddr = *addr;
    });

    const uint8_t connectResult = client.connect(address, port, std::chrono::seconds(OUTBOUND_CONNECT_TIMEOUT));
    if (connectResult != 0) {
        std::cerr << "Network: outgoing connect to " << address << ":" << port
                  << " failed, code=" << static_cast<int>(connectResult) << std::endl;
        return result;                                                              // verification defaults to ConnectionError
    }

    const int fd = client.release();
    if (fd < 0) {
        std::cerr << "Network: TcpClient released invalid socket" << std::endl;
        return result;
    }

    // ── Transport handshake ───────────────────────────────────────────────────
    std::shared_ptr<Connection> connection;
    try {
        connection = std::make_shared<Connection>(fd, &remoteAddr, this->networkSecret.get(), this->config.sendQueueLimitBytes);
    } catch (const std::exception& e) {
        std::cerr << "Network: outgoing Connection construction failed: " << e.what() << std::endl;
        ::close(fd);
        return result;
    }

    if (connection->initHandshake() != 0) {
        std::cerr << "Network: initHandshake failed for " << address << ":" << port << std::endl;
        connection->close();
        return result;
    }

    const int handshakeResult = connection->waitForHandshake();
    if (handshakeResult < 0) {
        std::cerr << "Network: outgoing handshake failed for " << address << ":" << port
                  << ", code=" << handshakeResult << std::endl;
        connection->close();
        return result;
    }

    // ── Identity verification ─────────────────────────────────────────────────
    PeerIdentity  remoteIdentity;
    IdentityFlags remoteFlags;
    const VerificationResult vr = IdentityVerification::runAsInitiator(
            *connection, *this->selfIdentity, this->config.nodeName,
            flagsSelf, remoteIdentity, remoteFlags
    );

    if (vr != VerificationResult::Success) {
        std::cerr << "Network: outgoing identity verification failed for " << address << ":" << port
                  << ", result=" << static_cast<int>(vr) << std::endl;
        connection->close();
        result.verification = vr;
        return result;
    }

    // ── Success — populate result ─────────────────────────────────────────────
    result.verification   = VerificationResult::Success;
    result.connection     = std::move(connection);
    result.remoteIdentity = std::move(remoteIdentity);
    result.remoteFlags    = remoteFlags;
    return result;
}

void Network::runOutgoingHandshake(std::string address, uint16_t port, HandshakeWorker* self) {
    blockSigpipeInCurrentThread();

    // Normal connect — no probe, no special flags
    OutboundConnectionResult result = this->establishOutboundConnection(address, port, IdentityFlags{});

    if (result.verification != VerificationResult::Success) {
        // Notify the per-peer backoff tracker so TopologyPlanner won't redial this address immediately.
        // Address-based lookup — we may not know the peerId if establishOutboundConnection failed
        // before identity verification.
        this->recordConnectionAttemptFailure(address, port);
        self->done.store(true, std::memory_order_release);
        return;
    }

    // Hand the live Connection + verified identity to the I/O thread for peer registration
    auto peer = std::make_shared<Peer>(std::move(result.connection), std::move(result.remoteIdentity), true);

    Command cmd;
    cmd.type = Command::Type::AddPeer;
    cmd.peer = std::move(peer);
    this->commandQueue.push(std::move(cmd));
    this->wakeupIoThread();

    self->done.store(true, std::memory_order_release);
}

void Network::recordConnectionAttemptFailure(const std::string& address, uint16_t port) {
    // Find peer by address+port match. We can't key by PeerId — failure may have happened
    // before identity verification revealed the remote's PeerId.
    // Two-step approach: snapshot directory under shared lock to find the match, then mutate
    // the matched entry under exclusive lock. A concurrent record update in between is harmless:
    // worst case we increment a stale failure counter that gets reset on the next outboundMatch.
    PeerId matchedId{};
    bool   found = false;

    {
        const auto allPeers = this->peerDirectory->listPeers();
        for (const auto& entry : allPeers) {
            for (const auto& addr : entry.record.addresses) {
                if (addr.address == address && addr.port == port) {
                    matchedId = entry.record.peerId;
                    found     = true;
                    break;
                }
            }
            if (found) break;
        }
    }

    if (!found) return;

    uint8_t              newFailureCount = 0;
    std::chrono::seconds waitDuration{0};

    const bool mutated = this->peerDirectory->mutatePeer(matchedId, [&](KnownPeer& entry) {
        if (entry.consecutiveConnectionFailures < BACKOFF_SCHEDULE_LEN) {
            ++entry.consecutiveConnectionFailures;
        }
        waitDuration = computeBackoffInterval(entry.consecutiveConnectionFailures);
        entry.nextConnectionAttemptAt = std::chrono::steady_clock::now() + waitDuration;
        newFailureCount = entry.consecutiveConnectionFailures;
    });

    if (!mutated) return;                                                           // peer was removed between snapshot and mutate

    std::cerr << "Network: connection failure recorded for " << peerIdShort(matchedId)
              << " (failures=" << static_cast<int>(newFailureCount)
              << ", next attempt in " << waitDuration.count() << "s)" << std::endl;

    this->demoteAfterRepeatedDialFailures(matchedId, newFailureCount);
}

void Network::demoteAfterRepeatedDialFailures(const PeerId& peerId, uint8_t consecutiveFailures) {
    if (consecutiveFailures < this->config.connectionFailuresBeforeUnavailable) return;

    // Only Available is demoted: Unknown/Unavailable already belong to the probe, and a Probing peer gets its state from
    // the probe result. The probe backoff is left as is — the probe channel stays independent of the dial channel, and a
    // later probe success does not reset dial backoff either (a peer that accepts probes but rejects connections must not
    // cycle Available ↔ Unavailable every few seconds).
    bool demoted = false;
    this->peerDirectory->mutatePeer(peerId, [&](KnownPeer& entry) {
        if (entry.availability != AvailabilityState::Available) return;
        entry.availability = AvailabilityState::Unavailable;
        demoted = true;
    });

    if (demoted) {
        std::cerr << "Network: " << peerIdShort(peerId) << " unreachable after " << static_cast<int>(consecutiveFailures)
                  << " failed dials, handing it to the probe" << std::endl;
    }
}

void Network::joinFinishedHandshakeWorkers() {
    std::lock_guard lock(this->handshakeWorkersMutex);
    this->handshakeWorkers.erase(
            std::remove_if(
                    this->handshakeWorkers.begin(),
                    this->handshakeWorkers.end(),
                    [](std::unique_ptr<HandshakeWorker>& w) {
                        if (w->done.load(std::memory_order_acquire)) {
                            if (w->thread.joinable()) w->thread.join();
                            return true;
                        }
                        return false;
                    }
            ),
            this->handshakeWorkers.end()
    );
}

// ============================================================
// Dedup / tie-break
// ============================================================

bool Network::shouldReplaceExistingPeer(const Peer& existing, const Peer& candidate) const {
    if (existing.getPeerId() != candidate.getPeerId()) return false;

    const PeerId& myId     = this->selfIdentity->getPeerId();
    const PeerId& remoteId = candidate.getPeerId();

    const bool weAreSmaller               = myId < remoteId;
    const bool winningDirectionIsOutbound = weAreSmaller;

    if (existing.isOutbound()  == winningDirectionIsOutbound) return false;
    if (candidate.isOutbound() == winningDirectionIsOutbound) return true;
    return false;
}

// ============================================================
// I/O thread
// ============================================================

void Network::ioLoop() {
    blockSigpipeInCurrentThread();
    std::vector<pollfd> fds;
    fds.reserve(64);

    // Connection-side events that mean "something happened, handle it":
    //   POLLIN    — data available (or EOF, which recv() returns as 0)
    //   POLLHUP   — remote closed the connection (may arrive without POLLIN if recv buffer is already drained)
    //   POLLERR   — socket error condition
    //   POLLNVAL  — fd is not open (should not happen, but if it does we must not busy-loop on it)
    //
    // Without handling POLLHUP here, a half-closed socket causes a tight 100% CPU loop: poll() keeps
    // returning the fd as ready, but we only reacted to POLLIN, so the peer never gets marked for close.
    constexpr short CONN_READY_FLAGS = POLLIN | POLLHUP | POLLERR | POLLNVAL;

    while (this->running.load()) {
        fds.clear();
        fds.push_back({ this->wakeupPipe[0], POLLIN, 0 });

        {
            std::shared_lock lock(this->peersMutex);
            fds.reserve(fds.size() + this->peersBySocket.size());
            for (const auto& [fd, peer] : this->peersBySocket) {
                if (peer->getState() == PeerState::Closing) continue;               // let cleanClosedPeers reap — no need to poll further

                // A peer that has not read any of our queued frames for sendStallTimeout is gone or hostile — it would
                // otherwise pin its full send queue in memory for as long as TCP keeps the connection open.
                const auto sendIdle = peer->timeSinceSendProgress();                // nullopt — nothing queued
                if (sendIdle && *sendIdle > this->config.sendStallTimeout) {
                    std::cerr << "Network: peer " << peerIdShort(peer->getPeerId()) << " stopped reading (send stalled), closing" << std::endl;
                    peer->markForClose();
                    continue;
                }

                const short events = sendIdle ? static_cast<short>(POLLIN | POLLOUT) : POLLIN;   // POLLOUT only with data waiting, or poll() spins
                fds.push_back({ fd, events, 0 });
            }
        }

        const int ready = ::poll(fds.data(), fds.size(), POLL_TIMEOUT_MS);
        if (ready < 0) {
            if (errno == EINTR) continue;
            std::cerr << "Network::ioLoop: poll() failed errno=" << errno << std::endl;
            break;
        }

        if (ready > 0) {
            for (const auto& pfd : fds) {
                if (pfd.fd == this->wakeupPipe[0]) {
                    if (pfd.revents & POLLIN) this->handleWakeup();
                } else {
                    if (pfd.revents & POLLOUT) this->handleConnectionWritable(pfd.fd);

                    // For connection fds, treat POLLIN/HUP/ERR/NVAL uniformly — all imply
                    // either incoming data or a terminal state we must react to.
                    if (pfd.revents & CONN_READY_FLAGS) {
                        this->handleConnectionReadable(pfd.fd, pfd.revents);
                    }
                }
            }
        }

        this->cleanClosedPeers();
    }
}

void Network::handleWakeup() {
    char buf[WAKEUP_DRAIN_BUFFER];
    while (::read(this->wakeupPipe[0], buf, sizeof(buf)) > 0) { }

    Command cmd;
    while (this->commandQueue.tryPop(cmd)) {
        switch (cmd.type) {
            case Command::Type::AddPeer: {
                if (!cmd.peer) break;

                if (cmd.peer->getPeerId() == this->selfIdentity->getPeerId()) {
                    std::cerr << "Network: rejecting self-connection attempt" << std::endl;
                    cmd.peer->markForClose();
                    cmd.peer->closeConnection();
                    break;
                }

                const int fd = cmd.peer->getSocket();
                if (fd < 0) {
                    cmd.peer->markForClose();
                    break;
                }

                {
                    std::shared_lock lock(this->peersMutex);
                    const size_t inboundCount = std::count_if(this->peersById.begin(), this->peersById.end(),
                                                              [](const auto& kv) { return !kv.second->isOutbound(); });
                    if (!cmd.peer->isOutbound() && inboundCount >= this->config.maxInbound) {
                        lock.unlock();
                        this->sendInitialPexTo(cmd.peer);                                           // give them peers before leaving
                        this->sendGoodbyeTo(cmd.peer, GoodbyeReason::NoSlots);
                        cmd.peer->closeConnection();
                        std::cerr << "Network: rejected inbound peer (NoSlots), maxInbound="
                                  << static_cast<int>(this->config.maxInbound) << std::endl;
                        break;
                    }
                }

                std::shared_ptr<Peer> insertedPeer;                                 // set if peer was added → schedule HELLO + notify after unlock
                std::shared_ptr<Peer> replacedPeer;                                 // set if tie-break swapped connections → close after unlock
                {
                    std::unique_lock lock(this->peersMutex);

                    const auto existingIt = this->peersById.find(cmd.peer->getPeerId());
                    if (existingIt != this->peersById.end()) {
                        if (this->shouldReplaceExistingPeer(*existingIt->second, *cmd.peer)) {
                            replacedPeer = existingIt->second;
                            replacedPeer->markForClose();
                            this->peersBySocket.erase(replacedPeer->getSocket());
                            existingIt->second = cmd.peer;
                            this->peersBySocket[fd] = cmd.peer;
                            cmd.peer->markActive();
                            insertedPeer = cmd.peer;
                            std::cerr << "Network: replaced existing peer (tie-break favored new connection)" << std::endl;
                        } else {
                            lock.unlock();
                            cmd.peer->markForClose();
                            cmd.peer->closeConnection();
                            std::cerr << "Network: rejected duplicate peer (tie-break favored existing)" << std::endl;
                        }
                    } else {
                        this->peersById[cmd.peer->getPeerId()] = cmd.peer;
                        this->peersBySocket[fd]                = cmd.peer;
                        cmd.peer->markActive();
                        insertedPeer = cmd.peer;
                        std::cerr << "Network: peer added " << peerIdShort(cmd.peer->getPeerId())
                                  << ", total=" << this->peersById.size() << std::endl;
                    }
                }

                // The replaced peer is no longer in any map, so cleanClosedPeers will never see it — close it here.
                if (replacedPeer) replacedPeer->closeConnection();

                // Schedule HELLO send from Management thread — keeps actual send off the I/O path. Also on
                // replacement: a HELLO queued for the old connection is skipped once that peer is Closing.
                // Notify listeners after Network-internal state is fully consistent (peer in maps,
                // HELLO scheduled). Listener callbacks run on this I/O thread. A replacement is transparent
                // to listeners — the peer stays connected, only the underlying connection changed.
                if (insertedPeer) {
                    this->scheduleHelloSend(insertedPeer);
                    if (!replacedPeer) this->notifyPeerConnected(insertedPeer->getIdentity());
                }
                break;
            }
        }
    }
}

void Network::handleConnectionReadable(int fd, short revents) {
    std::shared_ptr<Peer> peer;
    {
        std::shared_lock lock(this->peersMutex);
        const auto it = this->peersBySocket.find(fd);
        if (it == this->peersBySocket.end()) return;
        peer = it->second;
    }

    if (!peer->isActive()) return;

    // Terminal socket conditions — remote peer closed, socket error, or fd became invalid.
    // We still want to drain any remaining decoded frames from Connection's internal buffer before
    // closing (peer may have sent final frames just before FIN), but we must close afterwards
    // regardless — no more data will ever arrive on this socket.
    const bool terminalEvent = (revents & (POLLHUP | POLLERR | POLLNVAL)) != 0;

    while (true) {
        std::vector<uint8_t> message;
        ssize_t              n;

        try {
            n = peer->getConnection()->receive(message, std::chrono::milliseconds(0));
        } catch (const std::exception& e) {
            std::cerr << "Network: receive threw exception for peer "
                      << peerIdShort(peer->getPeerId()) << ": " << e.what() << std::endl;
            peer->markForClose();
            return;
        } catch (...) {
            std::cerr << "Network: receive threw unknown exception for peer "
                      << peerIdShort(peer->getPeerId()) << std::endl;
            peer->markForClose();
            return;
        }

        if (n > 0) {
            this->parseAndDispatchFrame(peer, std::move(message));
            continue;                                                               // keep draining buffered frames
        }

        if (n < 0) {
            std::cerr << "Network: receive error " << n << " from peer "
                      << peerIdShort(peer->getPeerId()) << ", closing" << std::endl;
            peer->markForClose();
            return;
        }

        // n == 0 — no complete frame available right now. Two sub-cases:
        //   - normal case (POLLIN only): peer is still alive, return to poll and wait for more
        //   - terminal event (POLLHUP/ERR/NVAL) without new data: the socket is done. If we don't
        //     close now, poll() will keep firing this revent forever and busy-loop the I/O thread.
        if (terminalEvent) {
            std::cerr << "Network: peer " << peerIdShort(peer->getPeerId())
                      << " socket closed by remote (revents=0x" << std::hex << revents << std::dec
                      << "), closing" << std::endl;
            peer->markForClose();
        }
        return;
    }
}

void Network::handleConnectionWritable(int fd) {
    std::shared_ptr<Peer> peer;
    {
        std::shared_lock lock(this->peersMutex);
        const auto it = this->peersBySocket.find(fd);
        if (it == this->peersBySocket.end()) return;
        peer = it->second;
    }

    if (!peer->isActive()) return;

    const ssize_t written = peer->writeQueuedFrames();                              // a failure marks the peer for close
    if (written < 0) {
        std::cerr << "Network: send error " << written << " to peer " << peerIdShort(peer->getPeerId()) << ", closing" << std::endl;
    }
}

void Network::parseAndDispatchFrame(const std::shared_ptr<Peer>& peer, std::vector<uint8_t> message) {
    if (message.size() < FRAME_HEADER_SIZE) {
        std::cerr << "Network: malformed frame (size=" << message.size()
                  << "B) from peer " << peerIdShort(peer->getPeerId()) << ", closing" << std::endl;
        peer->markForClose();
        return;
    }

    const uint8_t  group   = message[0];
    const uint16_t subtype = static_cast<uint16_t>(message[1]) << 8 | message[2];
    std::vector<uint8_t> payload(message.begin() + FRAME_HEADER_SIZE, message.end());

    if (group == GROUP_INTERNAL) {
        ProtocolMessage pm;
        pm.peer    = peer;
        pm.subtype = subtype;
        pm.payload = std::move(payload);
        if (peer->isOutbound()) pm.dialedAddress = peer->getConnection()->getRemoteClientAddress();
        this->messageProtocolQueue.push(std::move(pm));
    } else {
        NetworkMessage nm;
        nm.source  = peer->getPeerId();
        nm.group   = group;
        nm.subtype = subtype;
        nm.payload = std::move(payload);
        this->routerMessageQueue.push(std::move(nm));
    }
}

void Network::cleanClosedPeers() {
    std::vector<std::shared_ptr<Peer>> toClose;

    {
        std::unique_lock lock(this->peersMutex);
        for (auto it = this->peersById.begin(); it != this->peersById.end(); ) {
            if (it->second->getState() == PeerState::Closing) {
                toClose.push_back(it->second);
                this->peersBySocket.erase(it->second->getSocket());
                it = this->peersById.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (auto& peer : toClose) peer->closeConnection();

    // Fire disconnect events outside the peersMutex. Skip when not running — Network::stop()
    // tears down all peers without per-peer events; listeners treat shutdown as implicit
    // disconnection. This makes the event stream predictable: either the peer leaves while
    // Network is alive (event fires) or Network itself shuts down (no events).
    if (this->running.load()) {
        for (const auto& peer : toClose) {
            this->notifyPeerDisconnected(peer->getPeerId());
        }
    }

    if (!toClose.empty()) {
        std::cerr << "Network: closed " << toClose.size() << " peer(s), remaining="
                  << this->getConnectedPeerCount() << std::endl;
    }
}

// ============================================================
// Management thread
// ============================================================
void Network::managementLoop() {
    blockSigpipeInCurrentThread();

    auto lastBroadcastTick = std::chrono::steady_clock::now();
    auto topologyNextTick = std::chrono::steady_clock::now();
    auto periodicPexNextTick = std::chrono::steady_clock::now() + this->pickRandomPexInterval();
    constexpr auto BROADCAST_TICK_INTERVAL = std::chrono::seconds(1);

    while (this->running.load()) {
        this->joinFinishedHandshakeWorkers();
        const auto now = std::chrono::steady_clock::now();

        // Drain helloSendQueue — any peers scheduled for HELLO get the send now
        std::shared_ptr<Peer> helloTarget;
        while (this->helloSendQueue.tryPop(helloTarget)) {
            if (helloTarget && helloTarget->isActive()) {
                this->sendHelloTo(helloTarget);
                this->sendInitialPexTo(helloTarget);
            }
        }

        if (now >= topologyNextTick) {
            topologyNextTick = now + this->tickTopology();
        }

        // Periodic PEX broadcast — one announcement per second max, to spread load over time
        if (now - lastBroadcastTick >= BROADCAST_TICK_INTERVAL) {
            this->sendPendingPexBroadcasts();
            lastBroadcastTick = now;
        }
        if (now >= periodicPexNextTick) {
            this->tickPeriodicPex();
            periodicPexNextTick = now + this->pickRandomPexInterval();
        }

        // Probe scheduling — at most one in flight, throttled internally
        this->runPeerProbe();

        // Wait for internal (0xFF) messages with short timeout so periodic tasks aren't starved
        auto msg = this->messageProtocolQueue.waitPop(std::chrono::milliseconds(100));
        if (msg) {
            this->dispatchProtocolMessage(*msg);
        }

        // TODO: ping, reputation updates, peer storage flush
    }
}

void Network::dispatchProtocolMessage(const ProtocolMessage& msg) {
    if (!msg.peer || !msg.peer->isActive()) return;

    switch (msg.subtype) {
        case SUBTYPE_HELLO:
            this->processHelloMessage(msg);
            break;

        case SUBTYPE_PEX_ANNOUNCE:
            this->processPexAnnounceMessage(msg);
            break;

        case SUBTYPE_GOODBYE:
            this->processGoodbyeMessage(msg);
            break;

        default:
            std::cerr << "Network: unknown 0xFF subtype=0x" << std::hex << msg.subtype
                      << std::dec << " from peer " << peerIdShort(msg.peer->getPeerId())
                      << " payload=" << msg.payload.size() << "B, ignoring" << std::endl;
            break;
    }
}

std::chrono::milliseconds Network::tickTopology() {
    const PeerId& selfId = this->selfIdentity->getPeerId();

    std::vector<ConnectedPeerInfo> connected;
    {
        std::shared_lock lock(this->peersMutex);
        connected.reserve(this->peersById.size());
        for (const auto& [id, peer] : this->peersById)
            connected.push_back({ id, peer->isOutbound() });
    }

    // Snapshot directory once and filter locally — directory release happens before TopologyPlanner runs.
    std::vector<SignedPeerRecord> candidates;
    {
        const auto now      = std::chrono::steady_clock::now();
        const auto allPeers = this->peerDirectory->listPeers();
        for (const auto& entry : allPeers) {
            // TopologyPlanner only dials peers we have evidence are currently reachable.
            // hasEverConnected alone is not enough — a peer may have gone offline since.
            if (entry.availability != AvailabilityState::Available) continue;
            // Connection-attempt backoff — skip peers we just failed to dial. The cooldown grows
            // with consecutiveConnectionFailures (see computeBackoffInterval).
            if (now < entry.nextConnectionAttemptAt) continue;
            const PeerId& id = entry.record.peerId;
            if (id == selfId) continue;
            if (std::any_of(connected.begin(), connected.end(),
                            [&id](const ConnectedPeerInfo& p) { return p.peerId == id; })) continue;
            if (entry.record.addresses.empty()) continue;
            candidates.push_back(entry.record);
        }
    }

    const TopologyDecision decision = this->topologyPlanner.evaluate(connected, candidates, this->config);

    if (decision.connectTo) {
        // Take the peer out of the candidate list for as long as the attempt can last (R9) — otherwise the next ticks
        // (every 3 s) pick it again while the first handshake is still running. A failure overwrites this with the
        // backoff; a success makes it connected (excluded anyway) and its HELLO clears the field.
        this->peerDirectory->mutatePeer(decision.connectTo->peerId, [](KnownPeer& entry) {
            entry.nextConnectionAttemptAt = std::max(entry.nextConnectionAttemptAt, std::chrono::steady_clock::now() + OUTBOUND_ATTEMPT_MAX_DURATION);
        });

        std::cerr << "Network: topology — dialing " << decision.connectTo->address << ":" << decision.connectTo->port << std::endl;
        this->connectToPeer(decision.connectTo->address, decision.connectTo->port);
    }

    return decision.nextTick;
}

// ============================================================
// 0xFF protocol: HELLO
// ============================================================

void Network::scheduleHelloSend(std::shared_ptr<Peer> peer) {
    this->helloSendQueue.push(std::move(peer));
}

void Network::sendHelloTo(const std::shared_ptr<Peer>& peer) {
    if (this->selfRecordSerialized.empty()) return;                                 // defensive — start() builds this

    const std::vector<uint8_t> frame = buildFrame(GROUP_INTERNAL, SUBTYPE_HELLO, this->selfRecordSerialized);
    const ssize_t sent = this->sendFrameTo(peer, frame);

    if (sent < 0) {
        std::cerr << "Network: HELLO send to " << peerIdShort(peer->getPeerId())
                  << " failed (code=" << sent << ")" << std::endl;
    } else {
        std::cerr << "Network: sent HELLO to " << peerIdShort(peer->getPeerId())
                  << " (" << frame.size() << "B)" << std::endl;
    }
}

void Network::processHelloMessage(const ProtocolMessage& msg) {
    SignedPeerRecord record;
    const SignedRecordStatus status = SignedPeerRecordCodec::deserialize(msg.payload, record);

    if (status != SignedRecordStatus::Success) {
        std::cerr << "Network: HELLO from " << peerIdShort(msg.peer->getPeerId())
                  << " failed verification, status=" << static_cast<int>(status) << std::endl;
        return;
    }

    if (record.peerId != msg.peer->getPeerId()) {
        std::cerr << "Network: HELLO from " << peerIdShort(msg.peer->getPeerId())
                  << " described a different peerId (" << peerIdShort(record.peerId)
                  << "), discarding" << std::endl;
        return;
    }

    // Reachability check — same logic as before, delegated to the shared upsert helper.
    const bool outboundMatch = recordAnnouncesDialedAddress(record, msg.dialedAddress);

    const PeerId peerId          = record.peerId;                                   // save before move
    const bool   shouldBroadcast = this->upsertKnownPeer(std::move(record), outboundMatch);

    if (shouldBroadcast) {
        this->enqueuePexBroadcast(peerId, msg.peer->getPeerId());
    }

    std::cerr << "Network: HELLO processed from " << peerIdShort(msg.peer->getPeerId())
              << (outboundMatch ? ", verified" : ", unverified")
              << (shouldBroadcast ? ", broadcasting" : "")
              << ", knownPeers=" << this->peerDirectory->size() << std::endl;
}

void Network::sendGoodbyeTo(const std::shared_ptr<Peer>& peer, GoodbyeReason reason) {
    const std::vector<uint8_t> payload{ static_cast<uint8_t>(reason) };
    const std::vector<uint8_t> frame = buildFrame(GROUP_INTERNAL, SUBTYPE_GOODBYE, payload);
    this->sendFrameTo(peer, frame);  // best-effort — we're closing anyway, ignore send errors
    std::cerr << "Network: sent GOODBYE to " << peerIdShort(peer->getPeerId()) << " reason=" << static_cast<int>(reason) << std::endl;
}

void Network::processGoodbyeMessage(const ProtocolMessage& msg) {
    const GoodbyeReason reason = msg.payload.size() >= 1
                                 ? static_cast<GoodbyeReason>(msg.payload[0])
                                 : GoodbyeReason::Shutdown;  // malformed frame — treat as shutdown, close gracefully

    std::cerr << "Network: received GOODBYE from " << peerIdShort(msg.peer->getPeerId()) << " reason=" << static_cast<int>(reason) << std::endl;
    msg.peer->markForClose();
}

void Network::sendInitialPexTo(const std::shared_ptr<Peer>& peer) {
    const PeerId targetId = peer->getPeerId();

    // Snapshot the verified pool, excluding the target itself (no point in telling a peer about itself).
    // PEX promotes peers we have evidence ever worked — hasEverConnected is the gate.
    std::vector<SignedPeerRecord> verifiedPool;
    {
        const auto allPeers = this->peerDirectory->listPeers();
        verifiedPool.reserve(allPeers.size());
        for (const auto& entry : allPeers) {
            if (!entry.hasEverConnected)         continue;
            if (entry.record.peerId == targetId) continue;
            verifiedPool.push_back(entry.record);
        }
    }

    if (verifiedPool.empty()) return;                                               // nothing verified to share yet

    // Random sample up to initialPexBatchSize. If the pool is already smaller, take all of it.
    const size_t batchSize = std::min<size_t>(this->config.initialPexBatchSize, verifiedPool.size());

    std::vector<SignedPeerRecord> batch;
    batch.reserve(batchSize);

    if (batchSize == verifiedPool.size()) {
        batch = std::move(verifiedPool);
    } else {
        static thread_local std::mt19937 rng(std::random_device{}());
        std::sample(verifiedPool.begin(), verifiedPool.end(), std::back_inserter(batch), batchSize, rng);
    }

    const std::vector<uint8_t> payload = PexAnnounceCodec::serialize(batch);
    if (payload.empty()) return;

    const std::vector<uint8_t> frame = buildFrame(GROUP_INTERNAL, SUBTYPE_PEX_ANNOUNCE, payload);
    const ssize_t sent = this->sendFrameTo(peer, frame);

    if (sent <= 0) {
        std::cerr << "Network: initial PEX send to " << peerIdShort(targetId)
                  << " failed (code=" << sent << ")" << std::endl;
        return;
    }

    // Mark each sent record as just-announced so periodic anti-entropy doesn't re-pick them immediately.
    const auto now = std::chrono::steady_clock::now();
    for (const auto& record : batch) {
        this->peerDirectory->mutatePeer(record.peerId, [now](KnownPeer& kp) {
            kp.lastAnnouncedAt = now;
            ++kp.announceCount;
        });
    }

    std::cerr << "Network: sent initial PEX to " << peerIdShort(targetId)
              << " (" << batch.size() << " record(s), " << frame.size() << "B)" << std::endl;
}

// ============================================================
// Dispatch thread — drains routerMessageQueue and notifies listeners
// ============================================================

void Network::dispatchLoop() {
    blockSigpipeInCurrentThread();

    while (this->running.load()) {
        auto msg = this->routerMessageQueue.waitPop(std::chrono::milliseconds(100));
        if (!msg) continue;
        this->notifyMessageReceived(*msg);
    }
}

// ============================================================
// Common known-peer insert/update for HELLO and PEX_ANNOUNCE
// ============================================================
bool Network::upsertKnownPeer(SignedPeerRecord&& record, bool outboundMatch) {
    // outboundMatch == true means we just successfully connected to one of this record's
    // announced addresses, which is direct evidence that this peer is reachable RIGHT NOW.
    // It also counts as evidence that the peer has ever worked (hasEverConnected = true).
    // outboundMatch == false means we have no fresh evidence either way — availability stays
    // Unknown and a probe may upgrade it later.
    const PeerId peerId          = record.peerId;                                   // capture before move
    bool         shouldBroadcast = false;

    this->peerDirectory->upsertPeer(peerId, [&](KnownPeer& entry, bool isNewEntry) {
        const AvailabilityState newAvailability = outboundMatch
                                                  ? AvailabilityState::Available
                                                  : AvailabilityState::Unknown;

        if (isNewEntry) {
            // First time we see this peer.
            entry.record               = std::move(record);
            entry.pendingPexBroadcast  = true;
            entry.hasEverConnected     = outboundMatch;
            entry.availability         = newAvailability;
            // Backoff counters default to zero — fresh peer, no history.
            shouldBroadcast = outboundMatch;                                        // broadcast only if we have evidence it works
            return;
        }

        if (record.createdAt > entry.record.createdAt && hasSameAddressSet(record.addresses, entry.record.addresses)) {
            // Newer version, same addresses (e.g. the peer restarted and re-signed). The version bump says
            // nothing about reachability, so everything we learned about these addresses stays valid.
            // Only the gossip bookkeeping restarts, so the fresher version spreads like any new record.
            entry.record              = std::move(record);
            entry.announceCount       = 0;
            entry.pendingPexBroadcast = true;
            entry.lastAnnouncedAt     = {};
            if (outboundMatch) {
                entry.hasEverConnected              = true;
                entry.availability                  = AvailabilityState::Available;
                entry.consecutiveConnectionFailures = 0;
                entry.nextConnectionAttemptAt       = {};
                entry.consecutiveProbeFailures      = 0;
                entry.nextProbeAllowedAt            = {};
            }
            shouldBroadcast = entry.hasEverConnected;                               // only proven records are gossiped
            return;
        }

        if (record.createdAt > entry.record.createdAt) {
            // Newer record with a changed address set — previous reachability evidence and backoff
            // history were about other addresses and no longer apply. Reset everything to whatever
            // evidence this update brings. A Probing observer will detect the state change when
            // it tries to commit its result and skip the write.
            entry.record                          = std::move(record);
            entry.announceCount                   = 0;
            entry.pendingPexBroadcast             = true;
            entry.lastAnnouncedAt                 = {};
            entry.hasEverConnected                = outboundMatch;
            entry.availability                    = newAvailability;
            entry.consecutiveConnectionFailures   = 0;
            entry.nextConnectionAttemptAt         = {};
            entry.consecutiveProbeFailures        = 0;
            entry.nextProbeAllowedAt              = {};
            shouldBroadcast = outboundMatch;
            return;
        }

        // Same or older record — only allow upgrades. Never demote.
        // outboundMatch is fresh evidence both that the peer has ever worked AND is available now.
        if (outboundMatch) {
            const bool wasNotEverConnected = !entry.hasEverConnected;
            const bool wasNotAvailable     = entry.availability != AvailabilityState::Available;

            entry.hasEverConnected = true;
            entry.availability     = AvailabilityState::Available;
            // Reset both backoff counters — peer just successfully accepted a connection from us,
            // any history of failures (probe or connect) is no longer relevant.
            entry.consecutiveConnectionFailures = 0;
            entry.nextConnectionAttemptAt       = {};
            entry.consecutiveProbeFailures      = 0;
            entry.nextProbeAllowedAt            = {};

            // Broadcast if this is the first time we have evidence the peer ever worked.
            // A pure availability flip (was-Available → Available, hasEverConnected unchanged) is
            // not newsworthy for PEX — the record itself has not changed.
            shouldBroadcast = wasNotEverConnected || wasNotAvailable;
        }
        // else: same/older record without outboundMatch — no new information, no broadcast.
    });

    return shouldBroadcast;
}

void Network::processPexAnnounceMessage(const ProtocolMessage& msg) {
    std::vector<SignedPeerRecord> records;
    const PexAnnounceStatus status = PexAnnounceCodec::deserialize(msg.payload, records);

    if (status != PexAnnounceStatus::Success) {
        // Framing error — peer is broken or malicious. Drop the connection.
        // (Individual record verification failures are silently dropped by the codec and do not reach here.)
        std::cerr << "Network: PEX_ANNOUNCE from " << peerIdShort(msg.peer->getPeerId())
                  << " malformed, closing connection" << std::endl;
        msg.peer->markForClose();
        return;
    }

    const PeerId& selfId    = this->selfIdentity->getPeerId();
    const PeerId  senderId  = msg.peer->getPeerId();
    size_t        broadcastCount = 0;

    for (auto& record : records) {
        // Skip our own record — peer shouldn't announce us back to us
        if (record.peerId == selfId) continue;

        // If the announced record describes the sender itself, treat it like a HELLO update:
        // outbound match on the actual connection IP is valid evidence of reachability.
        // For records about other peers, we have no direct evidence — outboundMatch stays false
        // until a probe verifies reachability.
        const bool outboundMatch = record.peerId == senderId && recordAnnouncesDialedAddress(record, msg.dialedAddress);

        const PeerId peerId          = record.peerId;                               // save before move
        const bool   shouldBroadcast = this->upsertKnownPeer(std::move(record), outboundMatch);

        if (shouldBroadcast) {
            this->enqueuePexBroadcast(peerId, senderId);
            ++broadcastCount;
        }
    }

    std::cerr << "Network: PEX_ANNOUNCE from " << peerIdShort(senderId)
              << " — " << records.size() << " record(s), " << broadcastCount
              << " broadcasted, knownPeers=" << this->peerDirectory->size() << std::endl;
}

// ============================================================
// PEX broadcast queue
// ============================================================

void Network::enqueuePexBroadcast(const PeerId& recordPeerId, const PeerId& excludePeerId) {
    this->pexBroadcastQueue.push(PendingPexBroadcast{ recordPeerId, excludePeerId });
}

void Network::sendPendingPexBroadcasts() {
    // One announcement per tick — the caller's 1-second cadence provides rate limiting.
    PendingPexBroadcast pending;
    if (!this->pexBroadcastQueue.tryPop(pending)) return;

    // Fetch the current record. It may have been superseded by a newer version since
    // enqueuePexBroadcast was called; in that case we send the fresher one. Defensive
    // hasEverConnected check — the flag could have been cleared by a concurrent newer-record
    // update.
    const auto entry = this->peerDirectory->findPeer(pending.recordPeerId);
    if (!entry || !entry->hasEverConnected) return;

    // Serialize as a single-record batch — reuses the same codec as initial exchange and periodic tick
    const std::vector<SignedPeerRecord> batch{ entry->record };
    const std::vector<uint8_t> payload = PexAnnounceCodec::serialize(batch);
    if (payload.empty()) return;

    const std::vector<uint8_t> frame = buildFrame(GROUP_INTERNAL, SUBTYPE_PEX_ANNOUNCE, payload);

    // Snapshot connected peers under lock, then send outside the lock
    std::vector<std::shared_ptr<Peer>> targets;
    {
        std::shared_lock lock(this->peersMutex);
        targets.reserve(this->peersById.size());
        for (const auto& [id, peer] : this->peersById) {
            if (id == pending.excludePeerId) continue;
            targets.push_back(peer);
        }
    }

    size_t sent = 0;
    for (const auto& peer : targets) {
        if (this->sendFrameTo(peer, frame) > 0) ++sent;
    }

    // Mark as announced — also counts toward anti-entropy ordering. Clear pendingPexBroadcast
    // since this is the first broadcast for the record.
    const auto now = std::chrono::steady_clock::now();
    this->peerDirectory->mutatePeer(pending.recordPeerId, [now](KnownPeer& kp) {
        kp.lastAnnouncedAt     = now;
        ++kp.announceCount;
        kp.pendingPexBroadcast = false;
    });

    std::cerr << "Network: broadcasted PEX_ANNOUNCE for " << peerIdShort(pending.recordPeerId)
              << " to " << sent << "/" << targets.size() << " peer(s)" << std::endl;
}

// ============================================================
// Periodic anti-entropy PEX tick
// ============================================================

void Network::tickPeriodicPex() {
    // Snapshot pool of records we have evidence ever worked, with ordering key (lastAnnouncedAt).
    // listPeers() copies entries out of the directory under shared lock so we can sort/process freely.
    struct Candidate {
        std::chrono::steady_clock::time_point lastAnnouncedAt;
        SignedPeerRecord                      record;
    };

    std::vector<Candidate> pool;
    {
        const auto allPeers = this->peerDirectory->listPeers();
        pool.reserve(allPeers.size());
        for (const auto& entry : allPeers) {
            if (!entry.hasEverConnected) continue;
            pool.push_back({ entry.lastAnnouncedAt, entry.record });
        }
    }

    if (pool.empty()) return;                                                       // nothing to gossip

    // Pick N oldest-announced records — partial_sort is O(n log k), negligible here.
    const size_t batchSize = std::min<size_t>(this->config.periodicPexBatchSize, pool.size());
    std::partial_sort(pool.begin(), pool.begin() + batchSize, pool.end(),
                      [](const Candidate& a, const Candidate& b) { return a.lastAnnouncedAt < b.lastAnnouncedAt; });

    std::vector<SignedPeerRecord> batch;
    batch.reserve(batchSize);
    for (size_t i = 0; i < batchSize; ++i) batch.push_back(std::move(pool[i].record));

    const std::vector<uint8_t> payload = PexAnnounceCodec::serialize(batch);
    if (payload.empty()) return;

    const std::vector<uint8_t> frame = buildFrame(GROUP_INTERNAL, SUBTYPE_PEX_ANNOUNCE, payload);

    // Snapshot connected peers, send outside the lock
    std::vector<std::shared_ptr<Peer>> targets;
    {
        std::shared_lock lock(this->peersMutex);
        targets.reserve(this->peersById.size());
        for (const auto& [id, peer] : this->peersById) targets.push_back(peer);
    }

    if (targets.empty()) return;                                                    // no one connected — skip the update too

    size_t sent = 0;
    for (const auto& peer : targets) {
        if (this->sendFrameTo(peer, frame) > 0) ++sent;
    }

    // Update lastAnnouncedAt for each record in the batch. mutatePeer is a no-op for records
    // that were removed since the snapshot (future expiry/eviction).
    const auto now = std::chrono::steady_clock::now();
    for (const auto& record : batch) {
        this->peerDirectory->mutatePeer(record.peerId, [now](KnownPeer& kp) {
            kp.lastAnnouncedAt = now;
            ++kp.announceCount;
        });
    }

    std::cerr << "Network: anti-entropy PEX tick — " << batch.size() << " record(s) to "
              << sent << "/" << targets.size() << " peer(s)" << std::endl;
}

std::chrono::seconds Network::pickRandomPexInterval() {
    const auto minS = this->config.periodicPexMinInterval.count();
    const auto maxS = this->config.periodicPexMaxInterval.count();

    if (maxS <= minS) return std::chrono::seconds(minS);                            // degenerate config — fall back to min

    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<std::chrono::seconds::rep> dist(minS, maxS);
    return std::chrono::seconds(dist(rng));
}

// ============================================================
// Probe — reachability verification via one-shot outbound connection
// ============================================================

void Network::runPeerProbe() {
    // Single probe in flight at a time — prevents overlapping probe workers when many peers
    // are due. Per-peer cooldowns (nextProbeAllowedAt) prevent re-probing the same dead peer.
    if (this->probeInFlight.load(std::memory_order_acquire)) return;

    // Candidate selection: a peer eligible for probing must satisfy:
    //   - availability is Unknown (never tested) or Unavailable (failed before, cooldown elapsed)
    //   - per-peer probe cooldown has elapsed
    //   - has at least one announced address
    //   - is not us
    // Note: we do not skip peers we are already connected to. A connection we have does not
    // prove that the peer's announced address is reachable — they may be inbound-only (behind NAT)
    // or have announced a different address than the one they connected from. The probe bit in
    // IdentityVerification ensures a duplicate connection for probe purposes is rejected cleanly
    // by the remote without joining their peer pool, so there is no tie-break conflict.
    const auto   now    = std::chrono::steady_clock::now();
    const PeerId selfId = this->selfIdentity->getPeerId();

    // Snapshot all peers; filter eligible candidates locally without holding the directory lock.
    const auto allPeers = this->peerDirectory->listPeers();

    PeerId            pickedId{};
    PeerAddress       pickedAddr;
    AvailabilityState pickedPreviousAvailability = AvailabilityState::Unknown;    // restored if the worker cannot be started
    bool              picked = false;

    for (const auto& entry : allPeers) {
        if (entry.availability == AvailabilityState::Probing)   continue;
        if (entry.availability == AvailabilityState::Available) continue;
        if (now < entry.nextProbeAllowedAt)                     continue;
        if (entry.record.addresses.empty())                     continue;
        if (entry.record.peerId == selfId)                      continue;

        // Re-validate under exclusive lock and atomically transition to Probing.
        // Race-safe: state may have changed since listPeers() — mutator re-checks every condition
        // and only flips availability if still eligible. mutatePeer returns false if the peer was
        // removed in the meantime; we just continue to the next candidate.
        bool transitioned = false;
        this->peerDirectory->mutatePeer(entry.record.peerId, [&](KnownPeer& kp) {
            if (kp.availability == AvailabilityState::Probing)   return;
            if (kp.availability == AvailabilityState::Available) return;
            if (now < kp.nextProbeAllowedAt)                     return;
            if (kp.record.addresses.empty())                     return;
            pickedPreviousAvailability = kp.availability;
            kp.availability = AvailabilityState::Probing;
            transitioned    = true;
        });

        if (transitioned) {
            pickedId   = entry.record.peerId;
            pickedAddr = entry.record.addresses.front();                             // first address; future: try others on failure
            picked     = true;
            break;
        }
    }

    if (!picked) return;

    // Launch probe worker — same HandshakeWorker infra as other outbound workers
    auto  worker    = std::make_unique<HandshakeWorker>();
    auto* workerPtr = worker.get();

    const std::string address = pickedAddr.address;
    const uint16_t    port    = pickedAddr.port;

    // Raise the in-flight flag BEFORE the worker exists: the worker clears it when done, and a fast-failing
    // probe (e.g. connection refused) could otherwise clear it before we set it, leaving it stuck at true forever.
    this->probeInFlight.store(true, std::memory_order_release);

    try {
        worker->thread = std::thread([this, pickedId, address, port, workerPtr]() {
            this->runProbeWorker(pickedId, address, port, workerPtr);
        });
    } catch (const std::system_error& e) {
        // Thread creation failed (resource exhaustion) — undo the Probing transition so the peer stays eligible.
        this->peerDirectory->mutatePeer(pickedId, [&](KnownPeer& kp) {
            if (kp.availability == AvailabilityState::Probing) kp.availability = pickedPreviousAvailability;
        });
        this->probeInFlight.store(false, std::memory_order_release);
        std::cerr << "Network: failed to start probe worker for " << peerIdShort(pickedId) << ": " << e.what() << std::endl;
        return;
    }

    {
        std::lock_guard lock(this->handshakeWorkersMutex);
        this->handshakeWorkers.push_back(std::move(worker));
    }

    std::cerr << "Network: launched probe for " << peerIdShort(pickedId)
              << " at " << address << ":" << port << std::endl;
}

void Network::runProbeWorker(PeerId expected, std::string address, uint16_t port, HandshakeWorker* self) {
    blockSigpipeInCurrentThread();

    // Establish outbound connection with probe flag set — remote will close after verification.
    IdentityFlags flags;
    flags.setProbe(true);

    OutboundConnectionResult result = this->establishOutboundConnection(address, port, flags);

    bool success = false;

    if (result.verification != VerificationResult::Success) {
        std::cerr << "Network: probe to " << peerIdShort(expected)
                  << " at " << address << ":" << port
                  << " failed during handshake, result=" << static_cast<int>(result.verification) << std::endl;
    } else if (result.remoteIdentity.getPeerId() != expected) {
        // Someone else on that address — don't trust the address for the expected peer.
        // We don't record anything for the actual remote: our probe flag caused it to close without
        // sending HELLO, so we have no announced addresses to outbound-match against.
        std::cerr << "Network: probe to " << peerIdShort(expected)
                  << " at " << address << ":" << port
                  << " got PeerId mismatch (actual=" << peerIdShort(result.remoteIdentity.getPeerId())
                  << "), treating as probe failure" << std::endl;
    } else {
        // Identity verified, PeerId matches expected — the announced address is reachable.
        success = true;
        std::cerr << "Network: probe to " << peerIdShort(expected)
                  << " at " << address << ":" << port << " succeeded" << std::endl;
    }

    // Always close the connection — probe is one-shot.
    if (result.connection) result.connection->close();

    // Commit result to peerDirectory — this also updates the per-peer cooldown.
    this->commitProbeResult(expected, success);

    this->probeInFlight.store(false, std::memory_order_release);

    self->done.store(true, std::memory_order_release);
}

void Network::commitProbeResult(const PeerId& expected, bool success) {
    // Three possible outcomes after the mutation attempt:
    //   StateChanged — peer not found, OR availability is no longer Probing (newer record arrived
    //                  during probe and reset state). Don't overwrite.
    //   Success      — probe succeeded; mark Available, reset probe backoff, broadcast.
    //   Failed       — probe failed; mark Unavailable, increment counter, schedule next attempt.
    enum class Outcome { StateChanged, Success, Failed };
    Outcome              outcome       = Outcome::StateChanged;
    uint8_t              failureCount  = 0;
    std::chrono::seconds waitDuration{0};

    this->peerDirectory->mutatePeer(expected, [&](KnownPeer& entry) {
        if (entry.availability != AvailabilityState::Probing) return;               // outcome stays StateChanged

        if (success) {
            // Probe succeeded — mark Available AND record that we've ever had a working connection.
            // hasEverConnected may have been false (peer learned via PEX gossip with no direct
            // evidence yet); this probe is precisely that direct evidence.
            entry.availability              = AvailabilityState::Available;
            entry.hasEverConnected          = true;
            // Reset probe backoff — peer is back, history of past failures no longer matters.
            entry.consecutiveProbeFailures  = 0;
            entry.nextProbeAllowedAt        = {};
            outcome = Outcome::Success;
        } else {
            // Probe failed — increment counter, schedule next attempt according to backoff.
            // After the cooldown elapses, runPeerProbe will pick this peer up again
            // (Unavailable + nextProbeAllowedAt elapsed → eligible).
            entry.availability = AvailabilityState::Unavailable;
            if (entry.consecutiveProbeFailures < BACKOFF_SCHEDULE_LEN) {
                ++entry.consecutiveProbeFailures;
            }
            waitDuration = computeBackoffInterval(entry.consecutiveProbeFailures);
            entry.nextProbeAllowedAt = std::chrono::steady_clock::now() + waitDuration;
            failureCount = entry.consecutiveProbeFailures;
            outcome      = Outcome::Failed;
        }
    });

    // Logging and PEX-broadcast enqueue happen outside the directory lock.
    switch (outcome) {
        case Outcome::StateChanged:
            std::cerr << "Network: probe result for " << peerIdShort(expected)
                      << " ignored — state changed during probe" << std::endl;
            break;
        case Outcome::Failed:
            std::cerr << "Network: probe failure recorded for " << peerIdShort(expected)
                      << " (failures=" << static_cast<int>(failureCount)
                      << ", next probe in " << waitDuration.count() << "s)" << std::endl;
            break;
        case Outcome::Success:
            // excludePeerId = self — probe doesn't have a "source" peer to exclude; we learned
            // the record ourselves by verifying it directly.
            this->enqueuePexBroadcast(expected, this->selfIdentity->getPeerId());
            break;
    }
}

// ============================================================
// Helpers
// ============================================================

ssize_t Network::sendFrameTo(const std::shared_ptr<Peer>& peer, const std::vector<uint8_t>& frame) const {
    const ssize_t result = peer->send(frame);
    if (result > 0 && peer->hasQueuedFrames()) this->wakeupIoThread();
    return result;
}

void Network::wakeupIoThread() const {
    if (this->wakeupPipe[1] == -1) return;
    constexpr char byte = 'x';
    [[maybe_unused]] auto _ = ::write(this->wakeupPipe[1], &byte, 1);
}

void Network::markAllPeersForClose() {
    std::shared_lock lock(this->peersMutex);
    for (auto& [id, peer] : this->peersById) peer->markForClose();
}

void Network::finalCleanupAllPeers() {
    for (auto& [fd, peer] : this->peersBySocket) peer->closeConnection();
    this->peersBySocket.clear();
    this->peersById.clear();
}

} // namespace invilite::Mesh