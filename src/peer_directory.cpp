#include "meshlink/peer_directory.h"

namespace invilite::Mesh {

    std::optional<KnownPeer> PeerDirectory::findPeer(const PeerId& id) const {
        std::shared_lock lock(this->mutex_);
        const auto it = this->peers_.find(id);
        if (it == this->peers_.end()) return std::nullopt;
        return it->second;                                                                  // copy out under lock
    }

    std::vector<KnownPeer> PeerDirectory::listPeers() const {
        std::shared_lock lock(this->mutex_);
        std::vector<KnownPeer> out;
        out.reserve(this->peers_.size());
        for (const auto& [id, kp] : this->peers_) out.push_back(kp);
        return out;
    }

    size_t PeerDirectory::size() const {
        std::shared_lock lock(this->mutex_);
        return this->peers_.size();
    }

    void PeerDirectory::removePeer(const PeerId& id) {
        std::unique_lock lock(this->mutex_);
        this->peers_.erase(id);
    }

} // namespace invilite::Mesh