#include "meshlink/tree_root_election.h"

#include <algorithm>

namespace invilite::Mesh {

TreeRootElection::TreeRootElection(const PeerId& self, TreeRootConfig config) : self(self), config(config) {}

void TreeRootElection::start(std::chrono::steady_clock::time_point now, std::chrono::milliseconds listenFor) {
    this->started  = true;
    this->claiming = false;
    this->heardRoot.reset();
    this->claimAt  = now + listenFor;
}

std::vector<TreeRootChange> TreeRootElection::onBeacon(const PeerId& sender, std::chrono::steady_clock::time_point now) {
    if (!this->started || sender == this->self) return {};

    if (this->claiming) {
        if (!(sender < this->self)) return {};                                     // a larger claimer yields once it hears us
        this->claiming = false;
        this->heardRoot = sender;
        this->heardAt   = now;
        this->claimAt.reset();
        return { { TreeRootChange::Kind::Yielded, sender, this->self } };
    }

    const bool fresh = this->heardRoot && now < this->expiresAt();
    if (fresh && *this->heardRoot == sender) {
        this->heardAt = now;
        return {};
    }
    if (fresh && *this->heardRoot < sender) return {};                              // a larger one: it will yield to ours

    const std::optional<PeerId> previous = this->heardRoot;
    this->heardRoot = sender;
    this->heardAt   = now;
    if (sender < this->self) this->claimAt.reset();                                 // a smaller root: nothing to claim
    return { { TreeRootChange::Kind::Adopted, sender, previous } };
}

TreeRootElection::TickResult TreeRootElection::tick(std::chrono::steady_clock::time_point now, std::chrono::milliseconds listenAfterLoss) {
    TickResult result;
    if (!this->started) return result;

    if (this->heardRoot && now >= this->expiresAt()) {
        result.changes.push_back({ TreeRootChange::Kind::Lost, std::nullopt, this->heardRoot });
        this->heardRoot.reset();
    }

    if (this->claiming) {
        if (now >= this->nextBeaconAt) {
            result.sendBeacon  = true;
            this->nextBeaconAt = now + this->config.beaconInterval;
        }
        return result;
    }

    // Nobody smaller is heard: listen for a random while (the caller's draw), then claim — so that after a loss only a
    // few nodes claim at once, and a node smaller than the current root takes over without a stampede
    if (this->heardRoot && *this->heardRoot < this->self) return result;
    if (!this->claimAt) this->claimAt = now + listenAfterLoss;
    if (now < *this->claimAt) return result;

    result.changes.push_back({ TreeRootChange::Kind::Claimed, this->self, this->heardRoot });
    this->claiming = true;
    this->heardRoot.reset();
    this->claimAt.reset();
    result.sendBeacon  = true;
    this->nextBeaconAt = now + this->config.beaconInterval;
    return result;
}

std::optional<PeerId> TreeRootElection::root() const {
    if (this->claiming) return this->self;
    return this->heardRoot;
}

std::optional<std::chrono::steady_clock::time_point> TreeRootElection::nextDeadline() const {
    if (!this->started) return std::nullopt;
    if (this->claiming) return this->nextBeaconAt;
    std::optional<std::chrono::steady_clock::time_point> earliest = this->claimAt;
    if (this->heardRoot && (!earliest || this->expiresAt() < *earliest)) earliest = this->expiresAt();
    return earliest;
}

std::chrono::steady_clock::time_point TreeRootElection::expiresAt() const {
    return this->heardAt + this->config.beaconInterval * static_cast<int>(this->config.missedBeaconsToLose);
}

} // namespace invilite::Mesh
