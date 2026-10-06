#include "meshlink/peer.h"
#include "meshlink/errors.h"

invilite::Mesh::Peer::Peer(std::shared_ptr<Connection> connection, PeerIdentity identity, bool outbound, bool holePunched)
    : connection(std::move(connection)),
      identity(std::move(identity)),
      outbound(outbound),
      holePunched(holePunched),
      connectedAt(std::chrono::steady_clock::now()) {
}

int invilite::Mesh::Peer::getSocket() const {
    return this->connection ? this->connection->getSocket() : -1;
}

void invilite::Mesh::Peer::markActive() {
    // Only Joining → Active: never resurrect a peer that is already departing or closing
    PeerState expected = PeerState::Joining;
    this->state.compare_exchange_strong(expected, PeerState::Active, std::memory_order_acq_rel);
}

void invilite::Mesh::Peer::markForClose() {
    // Store Closing unconditionally — idempotent, covers all prior states
    this->state.store(PeerState::Closing, std::memory_order_release);
}

ssize_t invilite::Mesh::Peer::send(const std::vector<uint8_t>& data) {
    // The state check and the enqueue are not atomic: a frame may still slip in right after another thread moved the
    // peer to Departing (e.g. a user send racing stop()). The remote then closes on a non-0xFF frame in its window —
    // harmless; closing that gap would need protocol knowledge in Connection.
    // Joining peers are not driven by the I/O thread yet, Closing ones are being torn down. A close racing with this check
    // is harmless: Connection then reports SocketClosed.
    if (this->getState() != PeerState::Active || !this->connection) {
        return static_cast<ssize_t>(Error::Connection::SocketClosed);
    }

    const ssize_t result = this->connection->send(&data);
    if (result == static_cast<ssize_t>(Error::Connection::SocketError)) this->markForClose();
    return result;
}

bool invilite::Mesh::Peer::markDeparting() {
    PeerState expected = this->state.load(std::memory_order_acquire);
    while (expected == PeerState::Joining || expected == PeerState::Active) {
        if (this->state.compare_exchange_weak(expected, PeerState::Departing, std::memory_order_acq_rel)) {
            const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
            this->departingSinceTicks.store(now != 0 ? now : 1, std::memory_order_release);   // 0 is reserved for "never"
            return true;
        }
    }
    return false;
}

ssize_t invilite::Mesh::Peer::sendFarewell(const std::vector<uint8_t>& data) {
    if (this->getState() != PeerState::Departing || !this->connection) {
        return static_cast<ssize_t>(Error::Connection::SocketClosed);
    }
    const ssize_t result = this->connection->send(&data);
    if (result == static_cast<ssize_t>(Error::Connection::SocketError)) this->markForClose();
    return result;
}

void invilite::Mesh::Peer::finishSending() {
    if (this->connection) this->connection->finishSending();
}

ssize_t invilite::Mesh::Peer::writeQueuedFrames() {
    if (!this->connection) return static_cast<ssize_t>(Error::Connection::SocketClosed);
    const ssize_t result = this->connection->writeQueuedFrames();
    if (result < 0) this->markForClose();
    return result;
}

void invilite::Mesh::Peer::closeConnection() {
    if (this->connection) {
        this->connection->close();
    }
}
