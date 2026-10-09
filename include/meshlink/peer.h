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

// Transitions can happen on any thread, but only the I/O thread modifies peersById/peersBySocket.
enum class PeerState : uint8_t {
    Joining   = 0,
    Active    = 1,
    Departing = 2,                                                                  // departure window: last 0xFF messages only, still read by I/O
    Closing   = 3,                                                                  // marked for removal; the I/O thread reaps it in cleanClosedPeers
};

// One mesh connection to a verified peer. Methods are thread-safe where documented; send() never blocks
// (Connection queues what the socket cannot take).
class Peer {
public:
    // `holePunched`: the connection came from NAT hole punching; `outbound` then names the handshake initiator.
    Peer(std::shared_ptr<Connection> connection, PeerIdentity identity, bool outbound, bool holePunched = false);
    ~Peer() = default;

    Peer(const Peer&)            = delete;
    Peer& operator=(const Peer&) = delete;
    Peer(Peer&&)                 = delete;
    Peer& operator=(Peer&&)      = delete;

    [[nodiscard]] const PeerIdentity& getIdentity() const { return this->identity; }
    [[nodiscard]] const PeerId& getPeerId() const { return this->identity.getPeerId(); }
    [[nodiscard]] bool isOutbound() const { return this->outbound; }
    [[nodiscard]] bool wasHolePunched() const { return this->holePunched; }

    // Used by the I/O thread for poll() and recv().
    [[nodiscard]] int getSocket() const;
    [[nodiscard]] std::shared_ptr<Connection> getConnection() const { return this->connection; }

    [[nodiscard]] PeerState getState()  const { return this->state.load(std::memory_order_acquire); }
    [[nodiscard]] bool isActive()  const { return this->getState() == PeerState::Active; }

    // Called by the I/O thread after inserting the peer into peersById. Only Joining -> Active.
    void markActive();

    // Callable from any thread; idempotent. The I/O thread does the actual cleanup in cleanClosedPeers().
    void markForClose();

    // Enters the departure window from Joining or Active. False if the peer is already departing or closing.
    // Remembers when, so the owner can bound the window, and that it happened (wasEverDeparting).
    bool markDeparting();
    [[nodiscard]] bool isDeparting() const { return this->getState() == PeerState::Departing; }
    [[nodiscard]] std::chrono::steady_clock::time_point getDepartingSince() const { return std::chrono::steady_clock::time_point(std::chrono::steady_clock::duration(this->departingSinceTicks.load(std::memory_order_acquire))); }
    [[nodiscard]] bool wasEverDeparting() const { return this->departingSinceTicks.load(std::memory_order_acquire) != 0; }

    [[nodiscard]] std::chrono::steady_clock::time_point getConnectedAt() const { return this->connectedAt; }

    // Thread-safe, never blocks. Returns the bytes accepted (written or queued), or a negative error code.
    // Fails immediately if the peer is not Active. A failure that leaves the stream unusable marks the peer for close,
    // so callers only see the error.
    ssize_t send(const std::vector<uint8_t>& data);

    // Send queue: driven by the I/O thread.
    [[nodiscard]] bool hasQueuedFrames() const { return this->connection && this->connection->hasQueuedFrames(); }
    [[nodiscard]] std::optional<std::chrono::steady_clock::duration> timeSinceSendProgress() const { return this->connection ? this->connection->timeSinceSendProgress() : std::nullopt; }
    // Flushes queued frames when the socket is writable. Same error contract as send().
    ssize_t writeQueuedFrames();

    // The last frames to a Departing peer (farewell HELLO/PEX, GOODBYE). send() refuses non-Active peers, so ordinary
    // traffic can never reach a peer that is leaving. Same error contract as send().
    ssize_t sendFarewell(const std::vector<uint8_t>& data);
    // After the farewell frames: shut the write direction once they are flushed; reading continues.
    void finishSending();

    // Thread-safe: Connection serializes close with in-flight writes and drops any unsent frames.
    void closeConnection();

private:
    const std::shared_ptr<Connection>               connection;
    const PeerIdentity                              identity;
    const bool                                      outbound;
    const bool                                      holePunched;
    const std::chrono::steady_clock::time_point     connectedAt;

    std::atomic<PeerState>                          state{PeerState::Joining};
    std::atomic<std::chrono::steady_clock::rep>     departingSinceTicks{0};        // 0 = never departed
};

} // namespace invilite::Mesh

#endif // MESH_PEER_H