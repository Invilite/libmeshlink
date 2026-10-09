#pragma once

#include "meshlink/network.h"
#include "test_helpers.h"

#include <array>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>

namespace invilite::Mesh::TestHelpers {

inline bool waitUntil(const std::function<bool()>& condition, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (condition()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return condition();
}

struct TestNode {
    std::shared_ptr<LocalIdentity> identity  = std::make_shared<LocalIdentity>(LocalIdentity::generate());
    std::shared_ptr<PeerDirectory> directory = std::make_shared<PeerDirectory>();
    uint16_t                       port      = pickUnusedPort();
    std::unique_ptr<Network>       network;

    TestNode(const std::shared_ptr<std::array<uint8_t, 64>>& secret, const std::string& name, const std::function<void(NetworkConfig&)>& adjustConfig = {}, std::shared_ptr<Logger> logger = {}) {
        NetworkConfig config;
        config.listenPort         = this->port;
        config.nodeName           = name;
        config.announcedAddresses = { ipv4("127.0.0.1", this->port) };
        if (adjustConfig) adjustConfig(config);
        this->network = std::make_unique<Network>(this->identity, secret, this->directory, config, std::move(logger));
    }

    std::optional<KnownPeer> knownPeer(const TestNode& other) const { return this->directory->findPeer(other.identity->getPeerId()); }

    bool seesAsAvailable(const TestNode& other) const {
        const auto entry = this->knownPeer(other);
        return entry && entry->availability == AvailabilityState::Available;
    }
};

inline std::shared_ptr<std::array<uint8_t, 64>> makeSecret() {
    auto secret = std::make_shared<std::array<uint8_t, 64>>();
    secret->fill(0x42);
    return secret;
}

} // namespace invilite::Mesh::TestHelpers
