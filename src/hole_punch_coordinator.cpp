#include "meshlink/hole_punch_coordinator.h"

#include <algorithm>

namespace invilite::Mesh {

HolePunchCoordinator::HolePunchCoordinator(HolePunchCoordinatorConfig config) : config(config) {}

std::vector<HolePunchMessage> HolePunchCoordinator::onRequest(const PeerId& requester, const std::optional<HolePunchEndpoint>& requesterEndpoint, const HolePunchRequest& request,
                                                              const std::optional<HolePunchEndpoint>& targetEndpoint, const std::chrono::steady_clock::time_point now) {
    if (this->exchanges.contains(request.nonce)) return {};                         // replay or a nonce in use: never a second offer

    const auto decline = [&](HolePunchDeclineReason reason) {
        return std::vector<HolePunchMessage>{ { requester, HolePunchDecline{ request.nonce, reason } } };
    };

    // Rate limit first, so that even declines cannot be drawn out of us faster than one per interval
    const auto last = this->lastRequestAt.find(requester);
    if (last != this->lastRequestAt.end() && now - last->second < this->config.requestInterval) return decline(HolePunchDeclineReason::RateLimited);
    this->lastRequestAt[requester] = now;

    // Only the smaller PeerId asks, so crossed requests for one pair never arise
    if (!requesterEndpoint || !(requester < request.target)) return decline(HolePunchDeclineReason::NotAllowed);
    if (!targetEndpoint) return decline(HolePunchDeclineReason::NotNeighbor);
    // One public address for both: almost surely one LAN behind one NAT, and many routers do not loop traffic to their
    // own public address back in (hairpinning), so they should dial each other's local addresses
    if (this->config.sameNetworkShortcut && requesterEndpoint->address == targetEndpoint->address) return decline(HolePunchDeclineReason::SameNetwork);
    if (this->openExchangeCount() >= this->config.maxOpenExchanges) return decline(HolePunchDeclineReason::RateLimited);

    this->exchanges[request.nonce] = Exchange{ requester, request.target, *requesterEndpoint, *targetEndpoint, now + this->config.exchangeTimeout };
    return { { request.target, HolePunchOffer{ requester, request.nonce, *requesterEndpoint } } };
}

std::vector<HolePunchMessage> HolePunchCoordinator::onAccept(const PeerId& from, const HolePunchAccept& accept, const std::chrono::steady_clock::time_point now) {
    Exchange* exchange = this->findAnswerable(from, accept.nonce, now);
    if (exchange == nullptr) return {};
    exchange->finished = true;
    // Sent together, without evening out RTTs: the punch window absorbs the difference
    return {
        { exchange->requester, HolePunchNow{ accept.nonce, exchange->targetEndpoint } },
        { exchange->target,    HolePunchNow{ accept.nonce, exchange->requesterEndpoint } },
    };
}

std::vector<HolePunchMessage> HolePunchCoordinator::onDecline(const PeerId& from, const HolePunchDecline& decline, const std::chrono::steady_clock::time_point now) {
    Exchange* exchange = this->findAnswerable(from, decline.nonce, now);
    if (exchange == nullptr) return {};
    exchange->finished = true;
    return { { exchange->requester, decline } };
}

std::vector<HolePunchMessage> HolePunchCoordinator::onNeighborLost(const PeerId& peer) {
    std::vector<HolePunchMessage> out;
    for (auto& [nonce, exchange] : this->exchanges) {
        if (exchange.finished || (exchange.requester != peer && exchange.target != peer)) continue;
        exchange.finished = true;
        const PeerId& other = exchange.requester == peer ? exchange.target : exchange.requester;
        out.push_back({ other, HolePunchDecline{ nonce, HolePunchDeclineReason::PeerLeft } });
    }
    this->lastRequestAt.erase(peer);
    return out;
}

void HolePunchCoordinator::expire(const std::chrono::steady_clock::time_point now) {
    std::erase_if(this->exchanges, [now](const auto& entry) { return entry.second.deadline <= now; });
    std::erase_if(this->lastRequestAt, [&](const auto& entry) { return now - entry.second >= this->config.requestInterval; });
}

size_t HolePunchCoordinator::openExchangeCount() const {
    return static_cast<size_t>(std::count_if(this->exchanges.begin(), this->exchanges.end(), [](const auto& entry) { return !entry.second.finished; }));
}

HolePunchCoordinator::Exchange* HolePunchCoordinator::findAnswerable(const PeerId& from, const HolePunchNonce& nonce, const std::chrono::steady_clock::time_point now) {
    const auto it = this->exchanges.find(nonce);
    if (it == this->exchanges.end()) return nullptr;
    Exchange& exchange = it->second;
    if (exchange.finished || exchange.target != from || now >= exchange.deadline) return nullptr;
    return &exchange;
}

} // namespace invilite::Mesh
