#pragma once

#ifndef MESH_PEER_H
#define MESH_PEER_H

#include "meshlink/connection.h"
#include "meshlink/identity_verification.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <vector>

namespace invilite::Mesh {

// Peer lifecycle state. Atomic — transitions can happen from any thread,
// but peersById/peersBySocket are only modified by the I/O thread.
enum class PeerState : uint8_t {
    Joining = 0,                                                                    // handshake worker built Peer; not yet in peersById
    Active  = 1,                                                                    // inserted into peersById; available for send/receive
    Closing = 2,                                                                    // marked for removal; I/O thread will reap in cleanClosedPeers
};

// Peer — high-level abstraction over a single mesh connection.
// Owns a Connection (transport) + PeerIdentity (who we're talking to) + state.
// Methods are thread-safe where documented; send() never blocks (Connection queues what the socket cannot take).
class Peer {
public:
    Peer(std::shared_ptr<Connection> connection, PeerIdentity identity, bool outbound);
    ~Peer() = default;

    Peer(const Peer&)            = delete;
    Peer& operator=(const Peer&) = delete;
    Peer(Peer&&)                 = delete;
    Peer& operator=(Peer&&)      = delete;

    // ===== Identity accessors (immutable after construction) =====
    [[nodiscard]] const PeerIdentity& getIdentity() const { return this->identity; }
    [[nodiscard]] const PeerId& getPeerId() const { return this->identity.getPeerId(); }
    [[nodiscard]] bool isOutbound() const { return this->outbound; }

    // ===== Connection access — used by I/O thread for poll() and recv() =====
    [[nodiscard]] int getSocket() const;
    [[nodiscard]] std::shared_ptr<Connection> getConnection() const { return this->connection; }

    // ===== Lifecycle state (thread-safe) =====
    [[nodiscard]] PeerState getState()  const { return this->state.load(std::memory_order_acquire); }
    [[nodiscard]] bool isActive()  const { return this->getState() == PeerState::Active; }

    // Called by Network::I/O thread on successful insert into peersById
    void markActive();

    // Called by ANY thread to request peer removal.
    // Idempotent. I/O thread will perform actual cleanup in cleanClosedPeers().
    void markForClose();

    // ===== Statistics =====
    [[nodiscard]] std::chrono::steady_clock::time_point getConnectedAt() const { return this->connectedAt; }

    // ===== Send (thread-safe, non-blocking) =====
    // Returns bytes accepted (written or queued) on success, negative error code on failure.
    // Returns error immediately if peer is not in Active state. A failure that leaves the stream unusable marks the peer
    // for close — the peer owns its lifecycle, so callers only see the error.
    ssize_t send(const std::vector<uint8_t>& data);

    // ===== Send queue — driven by the I/O thread =====
    [[nodiscard]] bool hasQueuedFrames() const { return this->connection && this->connection->hasQueuedFrames(); }
    [[nodiscard]] std::optional<std::chrono::steady_clock::duration> timeSinceSendProgress() const { return this->connection ? this->connection->timeSinceSendProgress() : std::nullopt; }
    // Flush queued frames when the socket is writable. Same error contract as send().
    ssize_t writeQueuedFrames();

    // Close underlying Connection. Thread-safe: Connection serializes close with in-flight writes
    // and drops any unsent frames.
    void closeConnection();

private:
    const std::shared_ptr<Connection>               connection;                     // underlying transport, immutable ref
    const PeerIdentity                              identity;                       // verified remote identity, immutable
    const bool                                      outbound;                       // true if we initiated the connection
    const std::chrono::steady_clock::time_point     connectedAt;

    std::atomic<PeerState>                          state{PeerState::Joining};
};

} // namespace invilite::Mesh

#endif // MESH_PEER_H