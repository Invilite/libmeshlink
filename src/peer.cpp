#include "meshlink/peer.h"
#include "meshlink/errors.h"

invilite::Mesh::Peer::Peer(std::shared_ptr<Connection> connection, PeerIdentity identity, bool outbound)
    : connection(std::move(connection)),
      identity(std::move(identity)),
      outbound(outbound),
      connectedAt(std::chrono::steady_clock::now()) {
}

int invilite::Mesh::Peer::getSocket() const {
    return this->connection ? this->connection->getSocket() : -1;
}

void invilite::Mesh::Peer::markActive() {
    this->state.store(PeerState::Active, std::memory_order_release);
}

void invilite::Mesh::Peer::markForClose() {
    // Store Closing unconditionally — idempotent, covers all prior states
    this->state.store(PeerState::Closing, std::memory_order_release);
}

ssize_t invilite::Mesh::Peer::send(const std::vector<uint8_t>& data) {
    // Joining peers are not driven by the I/O thread yet, Closing ones are being torn down. A close racing with this check
    // is harmless: Connection then reports SocketClosed.
    if (this->getState() != PeerState::Active || !this->connection) {
        return static_cast<ssize_t>(Error::Connection::SocketClosed);
    }

    const ssize_t result = this->connection->send(&data);
    if (result == static_cast<ssize_t>(Error::Connection::SocketError)) this->markForClose();
    return result;
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
