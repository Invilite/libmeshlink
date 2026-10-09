#include <gtest/gtest.h>
#include "meshlink/peer_reachability.h"

using namespace invilite::Mesh;

TEST(PeerReachabilityTest, RecognizesPrivateAddresses) {
    for (const char* address : { "10.1.2.3", "172.16.1.10", "172.31.255.255", "192.168.0.1", "100.64.0.1", "100.127.255.255", "169.254.1.1",
                                 "127.0.0.1", "fd12:3456::1", "fe80::1", "::1", "::ffff:192.168.1.5" }) {
        EXPECT_TRUE(isPrivateAddress(address)) << address;
    }
    for (const char* address : { "203.0.113.7", "172.15.0.1", "172.32.0.1", "100.63.255.255", "100.128.0.1", "8.8.8.8",
                                 "2a01:4f8::1", "::ffff:8.8.8.8", "not-an-address", "" }) {
        EXPECT_FALSE(isPrivateAddress(address)) << address;
    }
}

// The case from the first real network: a node behind NAT announces its LAN address, the public node must not dial it
TEST(PeerReachabilityTest, PeerBehindNatKeepsOnlyAddressesReachableFromHere) {
    KnownPeer peer;
    peer.record.addresses = { { PeerAddress::Type::IPv4, "172.16.1.10", 8420 }, { PeerAddress::Type::IPv4, "203.0.113.7", 8420 },
                              { PeerAddress::Type::IPv4, "192.168.1.2", 8420 }, { PeerAddress::Type::IPv4, "198.51.100.1", 0 } };
    EXPECT_EQ(dialableAddresses(peer).size(), 3u);                                           // no evidence: all but port 0

    peer.reachedUsOverPublicInternet = true;
    const auto dialable = dialableAddresses(peer);
    ASSERT_EQ(dialable.size(), 1u);
    EXPECT_EQ(dialable.front().address, "203.0.113.7");
}

TEST(PeerReachabilityTest, HelloTellsWhereWeMet) {
    EXPECT_EQ(observedReachedUsOverPublicInternet("203.0.113.7", "", false), true);        // it dialed us through NAT
    EXPECT_EQ(observedReachedUsOverPublicInternet("192.168.1.2", "", false), false);         // same LAN
    EXPECT_EQ(observedReachedUsOverPublicInternet("", "10.0.0.5", true), false);             // we reached its private address
    EXPECT_EQ(observedReachedUsOverPublicInternet("", "203.0.113.7", true), std::nullopt);   // a public address says nothing about its private ones
    EXPECT_EQ(observedReachedUsOverPublicInternet("", "10.0.0.5", false), std::nullopt);     // dialed, but not an address it announces
}
