#include <gtest/gtest.h>
#include "meshlink/known_peer_eviction.h"

using namespace invilite::Mesh;
using namespace std::chrono_literals;

namespace {

KnownPeer entry(uint8_t tag, AvailabilityState availability, bool everConnected = false, uint8_t probeFailures = 0, std::chrono::seconds learnedAgo = 0s) {
    KnownPeer peer;
    peer.record.peerId[0]          = tag;
    peer.availability              = availability;
    peer.hasEverConnected          = everConnected;
    peer.consecutiveProbeFailures  = probeFailures;
    peer.firstLearnedAt            = std::chrono::steady_clock::now() - learnedAgo;
    return peer;
}

PeerId id(uint8_t tag) { PeerId peerId{}; peerId[0] = tag; return peerId; }

} // namespace

// Unreachable entries go first, the one that failed the most probes before the others.
TEST(KnownPeerEvictionTest, EvictsUnavailableWithMostFailedProbesFirst) {
    const std::vector<KnownPeer> book = { entry(1, AvailabilityState::Unknown, false, 0, 1h), entry(2, AvailabilityState::Unavailable, false, 2), entry(3, AvailabilityState::Unavailable, false, 5) };
    EXPECT_EQ(chooseEvictionVictim(book, {}, false), id(3));
}

// Without unreachable entries, the Unknown entry that has waited longest for a probe goes.
TEST(KnownPeerEvictionTest, ThenEvictsLongestWaitingUnknown) {
    const std::vector<KnownPeer> book = { entry(1, AvailabilityState::Unknown, false, 0, 10min), entry(2, AvailabilityState::Unknown, false, 0, 2h), entry(3, AvailabilityState::Unknown, false, 0, 1min) };
    EXPECT_EQ(chooseEvictionVictim(book, {}, false), id(2));
}

// Working peers are never evicted: Available, being probed, or connected right now (even if we never verified them,
// e.g. an inbound peer that is still Unknown).
TEST(KnownPeerEvictionTest, NeverEvictsAvailableProbingOrConnected) {
    const std::vector<KnownPeer> book = { entry(1, AvailabilityState::Available), entry(2, AvailabilityState::Probing), entry(3, AvailabilityState::Unknown, false, 0, 5h) };
    EXPECT_EQ(chooseEvictionVictim(book, { id(3) }, true), std::nullopt);
}

// An unverified newcomer must not push out an entry that once worked — that is what a flood of fake identities would
// do. A proven newcomer may, as a last resort, and then the proven entries are ordered like the rest.
TEST(KnownPeerEvictionTest, EverConnectedEntriesYieldOnlyToProvenRecords) {
    const std::vector<KnownPeer> book = { entry(1, AvailabilityState::Unavailable, true, 7), entry(2, AvailabilityState::Unknown, true, 0, 3h) };
    EXPECT_EQ(chooseEvictionVictim(book, {}, false), std::nullopt);
    EXPECT_EQ(chooseEvictionVictim(book, {}, true), id(1));
}

// Unverified entries always go before proven ones, whatever their other scores.
TEST(KnownPeerEvictionTest, UnverifiedEntriesGoBeforeEverConnectedOnes) {
    const std::vector<KnownPeer> book = { entry(1, AvailabilityState::Unavailable, true, 7), entry(2, AvailabilityState::Unknown, false, 0, 1s) };
    EXPECT_EQ(chooseEvictionVictim(book, {}, true), id(2));
}
