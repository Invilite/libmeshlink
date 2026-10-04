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
    std::lock_guard<std::mutex> lock(this->sendMutex);

    // Check state under sendMutex — guarantees no race with closeConnection.
    // If peer is Joining or Closing, refuse to send.
    if (this->getState() != PeerState::Active) {
        return static_cast<ssize_t>(Error::Connection::SocketClosed);
    }

    if (!this->connection) {
        return static_cast<ssize_t>(Error::Connection::SocketClosed);
    }

    return this->connection->send(&data);
}

void invilite::Mesh::Peer::closeConnection() {
    std::lock_guard<std::mutex> lock(this->sendMutex);                              // wait for any in-flight send to finish
    if (this->connection) {
        this->connection->close();
    }
}