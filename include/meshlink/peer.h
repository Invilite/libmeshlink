#pragma once

#ifndef MESH_PEER_H
#define MESH_PEER_H

#include "meshlink/connection.h"
#include "meshlink/identity_verification.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
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
// Methods are thread-safe where documented; send() uses an internal mutex.
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

    // ===== Send (thread-safe — serialized via sendMutex) =====
    // Returns bytes sent on success, negative error code on failure.
    // Returns error immediately if peer is not in Active state.
    ssize_t send(const std::vector<uint8_t>& data);

    // Close underlying Connection. Called by I/O thread during reap,
    // holds sendMutex to wait for any in-flight send to complete.
    void closeConnection();

private:
    const std::shared_ptr<Connection>               connection;                     // underlying transport, immutable ref
    const PeerIdentity                              identity;                       // verified remote identity, immutable
    const bool                                      outbound;                       // true if we initiated the connection
    const std::chrono::steady_clock::time_point     connectedAt;

    std::atomic<PeerState>                          state{PeerState::Joining};
    std::mutex                                      sendMutex;                      // serializes Connection::send, also held during close
};

} // namespace invilite::Mesh

#endif // MESH_PEER_H