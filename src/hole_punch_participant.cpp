#include "meshlink/hole_punch_participant.h"

#include <algorithm>

namespace invilite::Mesh {

HolePunchParticipant::HolePunchParticipant(const PeerId& self, HolePunchParticipantConfig config) : self(self), config(config) {}

std::optional<HolePunchMessage> HolePunchParticipant::request(const PeerId& target, const PeerId& via, const HolePunchNonce& nonce, const std::chrono::steady_clock::time_point now) {
    if (!holePunchInitiatesHandshake(this->self, target) || this->isExchangingWith(target) || this->isResting(target, now) || this->exchanges.contains(nonce)) return std::nullopt;
    this->exchanges[nonce] = Exchange{ target, via, Stage::Asked, now + this->config.exchangeTimeout };
    return HolePunchMessage{ via, HolePunchRequest{ target, nonce } };
}

std::optional<HolePunchMessage> HolePunchParticipant::onOffer(const PeerId& from, const HolePunchOffer& offer, const std::optional<HolePunchDeclineReason> localObstacle,
                                                              const std::chrono::steady_clock::time_point now) {
    if (this->exchanges.contains(offer.nonce)) return std::nullopt;                 // replay: answered already

    const auto decline = [&](HolePunchDeclineReason reason) { return HolePunchMessage{ from, HolePunchDecline{ offer.nonce, reason } }; };
    if (!holePunchInitiatesHandshake(offer.initiator, this->self)) return decline(HolePunchDeclineReason::NotAllowed);
    if (this->isExchangingWith(offer.initiator)) return decline(HolePunchDeclineReason::Busy);
    if (this->isResting(offer.initiator, now)) return decline(HolePunchDeclineReason::TooManyAttempts);
    if (localObstacle) return decline(*localObstacle);

    this->exchanges[offer.nonce] = Exchange{ offer.initiator, from, Stage::Accepted, now + this->config.exchangeTimeout };
    return HolePunchMessage{ from, HolePunchAccept{ offer.nonce } };
}

std::optional<HolePunchStart> HolePunchParticipant::onNow(const PeerId& from, const HolePunchNow& message, const std::chrono::steady_clock::time_point now) {
    const auto it = this->exchanges.find(message.nonce);
    if (it == this->exchanges.end()) return std::nullopt;
    Exchange& exchange = it->second;
    if (exchange.via != from || now >= exchange.deadline || (exchange.stage != Stage::Asked && exchange.stage != Stage::Accepted)) return std::nullopt;

    exchange.stage    = Stage::Punching;
    exchange.deadline = now + this->config.punchWindow;
    return HolePunchStart{ exchange.peer, exchange.via, message.remoteEndpoint, holePunchInitiatesHandshake(this->self, exchange.peer), exchange.deadline };
}

std::optional<HolePunchFailure> HolePunchParticipant::onDecline(const PeerId& from, const HolePunchDecline& decline, const std::chrono::steady_clock::time_point now) {
    const auto it = this->exchanges.find(decline.nonce);
    if (it == this->exchanges.end()) return std::nullopt;
    Exchange& exchange = it->second;
    if (exchange.via != from || now >= exchange.deadline || (exchange.stage != Stage::Asked && exchange.stage != Stage::Accepted)) return std::nullopt;

    exchange.stage = Stage::Ended;
    return HolePunchFailure{ exchange.peer, exchange.via, decline.reason };
}

std::vector<HolePunchFailure> HolePunchParticipant::onNeighborLost(const PeerId& peer) {
    std::vector<HolePunchFailure> failures;
    for (auto& [nonce, exchange] : this->exchanges) {
        if (exchange.via != peer || (exchange.stage != Stage::Asked && exchange.stage != Stage::Accepted)) continue;
        exchange.stage = Stage::Ended;
        failures.push_back({ exchange.peer, exchange.via, HolePunchDeclineReason::PeerLeft });
    }
    return failures;
}

void HolePunchParticipant::finishPunch(const PeerId& peer, const bool connected, const std::chrono::steady_clock::time_point now) {
    for (auto& [nonce, exchange] : this->exchanges) {
        if (exchange.peer == peer && exchange.stage == Stage::Punching) exchange.stage = Stage::Ended;
    }
    if (connected) this->pairFailures.erase(peer);
    else           this->recordFailedAttempt(peer, now);
}

void HolePunchParticipant::recordFailedAttempt(const PeerId& peer, const std::chrono::steady_clock::time_point now) {
    if (this->config.failureRest.empty()) return;
    auto& [failures, restUntil] = this->pairFailures[peer];
    restUntil = now + this->config.failureRest[std::min(failures, this->config.failureRest.size() - 1)];
    ++failures;
}

bool HolePunchParticipant::isResting(const PeerId& peer, const std::chrono::steady_clock::time_point now) const {
    const auto it = this->pairFailures.find(peer);
    return it != this->pairFailures.end() && now < it->second.second;
}

std::vector<HolePunchFailure> HolePunchParticipant::expire(const std::chrono::steady_clock::time_point now) {
    std::vector<HolePunchFailure> failures;
    std::erase_if(this->exchanges, [&](const auto& entry) {
        const Exchange& exchange = entry.second;
        if (exchange.deadline > now) return false;
        if (exchange.stage == Stage::Asked || exchange.stage == Stage::Accepted) failures.push_back({ exchange.peer, exchange.via, std::nullopt });
        return true;
    });
    return failures;
}

bool HolePunchParticipant::isExchangingWith(const PeerId& peer) const {
    return std::any_of(this->exchanges.begin(), this->exchanges.end(), [&](const auto& entry) { return entry.second.peer == peer && entry.second.stage != Stage::Ended; });
}

} // namespace invilite::Mesh
