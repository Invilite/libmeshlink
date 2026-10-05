#include <gtest/gtest.h>
#include "meshlink/plumtree_state.h"

#include <algorithm>

using namespace invilite::Mesh;
using namespace std::chrono_literals;

namespace {

const auto T0 = std::chrono::steady_clock::time_point(std::chrono::seconds(1000));

PeerId peerId(uint8_t fill) { PeerId id; id.fill(fill); return id; }

const PeerId A = peerId(0xA), B = peerId(0xB), C = peerId(0xC), ORIGIN = peerId(0x0F);

RoutedMessageKey key(uint64_t msgId) { return { ORIGIN, msgId }; }

std::vector<PeerId> sorted(std::vector<PeerId> peers) { std::sort(peers.begin(), peers.end()); return peers; }

PlumtreeState withLinks(std::initializer_list<PeerId> links, PlumtreeConfig config = {}) {
    PlumtreeState state(config);
    for (const PeerId& link : links) state.addLink(link);
    return state;
}

} // namespace

TEST(PlumtreeStateTest, NewLinksAreEagerSoFirstMessagesFlood) {
    PlumtreeState state = withLinks({ A, B, C, ORIGIN });
    for (const PeerId& link : { A, B, C }) EXPECT_TRUE(state.isEager(link));

    const auto decision = state.onNewMessage(key(1), A, true, T0);
    EXPECT_EQ(sorted(decision.fullCopyTo), sorted({ B, C }));                                // not back to A, not to the originator
    EXPECT_FALSE(decision.graftTo.has_value());
    EXPECT_FALSE(decision.pruneTo.has_value());
    EXPECT_FALSE(state.nextDeadline().has_value());                                          // nothing lazy, nothing to announce

    const RoutedMessageKey own{ peerId(0x55), 2 };                                             // we are the originator
    EXPECT_EQ(sorted(state.onNewMessage(own, std::nullopt, true, T0).fullCopyTo), sorted({ A, B, C, ORIGIN }));
}

TEST(PlumtreeStateTest, DuplicateFromEagerLinkPrunesIt) {
    PlumtreeState state = withLinks({ A, B });
    EXPECT_TRUE(state.onDuplicate(A, false));
    EXPECT_FALSE(state.isEager(A));
    EXPECT_FALSE(state.onDuplicate(A, false));                                               // already lazy: no second PRUNE
    EXPECT_FALSE(state.onDuplicate(B, true));                                                // a copy with higher TTL is a better path
    EXPECT_TRUE(state.isEager(B));
    EXPECT_FALSE(state.onDuplicate(C, false));                                               // not a link
}

TEST(PlumtreeStateTest, LazyLinksGetAnnouncementsInOneBatchPerInterval) {
    PlumtreeState state = withLinks({ A, B, C });
    state.onPrune(B);
    state.onPrune(C);

    const auto first = state.onNewMessage(key(1), A, true, T0);
    EXPECT_TRUE(first.fullCopyTo.empty());
    state.onNewMessage(key(2), C, true, T0 + 30ms);                                          // not announced back to C
    ASSERT_EQ(state.nextDeadline(), T0 + 100ms);

    EXPECT_TRUE(state.takeDueAnnouncements(T0 + 99ms).empty());
    const auto batch = state.takeDueAnnouncements(T0 + 100ms);
    ASSERT_EQ(batch.size(), 2u);
    EXPECT_EQ(batch.at(B), (std::vector<RoutedMessageKey>{ key(1), key(2) }));
    EXPECT_EQ(batch.at(C), (std::vector<RoutedMessageKey>{ key(1) }));
    EXPECT_EQ(batch.count(A), 0u);                                                           // A is eager, it got the full copy of key 2
    EXPECT_TRUE(state.takeDueAnnouncements(T0 + 1s).empty());
    EXPECT_FALSE(state.nextDeadline().has_value());
}

TEST(PlumtreeStateTest, MessageNotForwardedIsNeitherSentNorAnnounced) {
    PlumtreeState state = withLinks({ A, B, C });
    state.onPrune(C);
    state.onAnnouncement(C, { key(1) }, T0);
    const auto decision = state.onNewMessage(key(1), A, false, T0 + 10ms);
    EXPECT_TRUE(decision.fullCopyTo.empty());
    EXPECT_EQ(state.missingCount(), 0u);                                                     // it arrived: no GRAFT for it
    EXPECT_FALSE(state.nextDeadline().has_value());
}

TEST(PlumtreeStateTest, PruneAndGraftFromNeighborSwitchTheLink) {
    PlumtreeState state = withLinks({ A });
    state.onPrune(A);
    EXPECT_FALSE(state.isEager(A));
    state.onGraft(A);
    EXPECT_TRUE(state.isEager(A));
}

TEST(PlumtreeStateTest, MissingMessageIsGraftedFromAnnouncersInTurn) {
    PlumtreeState state = withLinks({ A, B, C });
    state.onPrune(A);
    state.onPrune(B);
    state.onAnnouncement(A, { key(1) }, T0);
    state.onAnnouncement(B, { key(1) }, T0 + 50ms);
    state.onAnnouncement(A, { key(1) }, T0 + 60ms);                                          // repeated announcer counted once
    ASSERT_EQ(state.nextDeadline(), T0 + 500ms);                                             // from the first announcement

    EXPECT_TRUE(state.takeDueGrafts(T0 + 499ms).empty());
    auto grafts = state.takeDueGrafts(T0 + 500ms);
    ASSERT_EQ(grafts.size(), 1u);
    EXPECT_EQ(grafts.at(A), (std::vector<RoutedMessageKey>{ key(1) }));
    EXPECT_TRUE(state.isEager(A));                                                           // GRAFT makes the link eager on our side too

    EXPECT_TRUE(state.takeDueGrafts(T0 + 999ms).empty());                                    // A gets a full period to answer
    grafts = state.takeDueGrafts(T0 + 1000ms);                                               // A did not deliver in time
    ASSERT_EQ(grafts.size(), 1u);
    EXPECT_EQ(grafts.at(B), (std::vector<RoutedMessageKey>{ key(1) }));

    EXPECT_TRUE(state.takeDueGrafts(T0 + 1500ms).empty());                                   // announcers used up: given up
    EXPECT_EQ(state.missingCount(), 0u);
}

TEST(PlumtreeStateTest, ArrivalCancelsPendingGraft) {
    PlumtreeState state = withLinks({ A, B });
    state.onPrune(B);
    state.onAnnouncement(B, { key(1) }, T0);
    state.onNewMessage(key(1), A, true, T0 + 20ms);
    EXPECT_TRUE(state.takeDueGrafts(T0 + 1s).empty());
    EXPECT_EQ(state.missingCount(), 0u);
}

TEST(PlumtreeStateTest, SlowEagerLinkIsSwappedForFasterAnnouncer) {
    PlumtreeState state = withLinks({ A, B });
    state.onPrune(B);                                                                        // A eager, B lazy

    state.onAnnouncement(B, { key(1) }, T0);
    const auto slow = state.onNewMessage(key(1), A, true, T0 + 51ms);                        // full copy later than the announcement by > 50 ms
    EXPECT_EQ(slow.graftTo, B);
    EXPECT_EQ(slow.pruneTo, A);
    EXPECT_TRUE(state.isEager(B));
    EXPECT_FALSE(state.isEager(A));
    EXPECT_TRUE(slow.fullCopyTo.empty());                                                    // B announced it (has it), A gave it

    state.onAnnouncement(A, { key(2) }, T0 + 1s);
    const auto close = state.onNewMessage(key(2), B, true, T0 + 1s + 50ms);                  // within the threshold
    EXPECT_FALSE(close.graftTo.has_value());
    EXPECT_FALSE(close.pruneTo.has_value());
    EXPECT_TRUE(state.isEager(B));
}

// Once we asked by GRAFT, the copy is the answer — no swap on top of it
TEST(PlumtreeStateTest, NoSwapAfterGraftWasSent) {
    PlumtreeState state = withLinks({ A, B, C });
    state.onPrune(B);
    state.onPrune(C);
    state.onAnnouncement(B, { key(1) }, T0);
    state.onAnnouncement(C, { key(1) }, T0);                                                 // a second announcer still waits its turn
    ASSERT_EQ(state.takeDueGrafts(T0 + 500ms).size(), 1u);
    const auto decision = state.onNewMessage(key(1), A, true, T0 + 600ms);
    EXPECT_FALSE(decision.graftTo.has_value());
    EXPECT_FALSE(decision.pruneTo.has_value());
    EXPECT_TRUE(state.isEager(A));
    EXPECT_FALSE(state.isEager(C));
}

TEST(PlumtreeStateTest, LosingEagerLinkTurnsLazyLinksEager) {
    PlumtreeState state = withLinks({ A, B, C });
    state.onPrune(B);
    state.onPrune(C);
    EXPECT_EQ(sorted(state.removeLink(A)), sorted({ B, C }));                                // fast repair: empty GRAFT to each
    EXPECT_TRUE(state.isEager(B));
    EXPECT_TRUE(state.isEager(C));
    EXPECT_FALSE(state.hasLink(A));

    state.onPrune(C);
    EXPECT_TRUE(state.removeLink(C).empty());                                                // a lazy link lost: nothing to repair
    EXPECT_TRUE(state.removeLink(A).empty());                                                // not a link any more
}

TEST(PlumtreeStateTest, RemovedLinkIsDroppedFromAnnouncementsAndAnnouncers) {
    PlumtreeState state = withLinks({ A, B, C });
    state.onPrune(B);
    state.onPrune(C);
    state.onNewMessage(key(1), A, true, T0);                                                 // queued for B and C
    state.onAnnouncement(C, { key(2) }, T0);
    state.removeLink(C);

    const auto batch = state.takeDueAnnouncements(T0 + 100ms);
    EXPECT_EQ(batch.count(C), 0u);
    EXPECT_EQ(batch.count(B), 1u);
    EXPECT_TRUE(state.takeDueGrafts(T0 + 500ms).empty());                                    // its only announcer left
    EXPECT_EQ(state.missingCount(), 0u);
}

TEST(PlumtreeStateTest, MissingMessagesAndAnnouncersAreBounded) {
    PlumtreeConfig config;
    config.maxMissingMessages      = 2;
    config.maxAnnouncersPerMessage = 1;
    PlumtreeState state = withLinks({ A, B }, config);
    state.onAnnouncement(A, { key(1), key(2), key(3) }, T0);
    EXPECT_EQ(state.missingCount(), 2u);

    state.onAnnouncement(B, { key(1) }, T0);
    const auto grafts = state.takeDueGrafts(T0 + 500ms);
    EXPECT_EQ(grafts.count(B), 0u);
    EXPECT_TRUE(state.takeDueGrafts(T0 + 1000ms).empty());                                   // only A was remembered for key 1
}

// A link that announced the message to us has it: neither a full copy nor an announcement back
TEST(PlumtreeStateTest, AnnouncersOfMessageAreSkipped) {
    PlumtreeState state = withLinks({ A, B, C });
    state.onPrune(C);
    state.onAnnouncement(B, { key(1) }, T0);
    state.onAnnouncement(C, { key(1) }, T0);
    const auto decision = state.onNewMessage(key(1), A, true, T0 + 10ms);
    EXPECT_TRUE(decision.fullCopyTo.empty());                                                // B is eager but announced it
    EXPECT_TRUE(state.takeDueAnnouncements(T0 + 1s).empty());                                // C is lazy but announced it

    // Also the announcer we already asked by GRAFT
    state.onPrune(B);
    state.onAnnouncement(B, { key(2) }, T0 + 2s);
    ASSERT_EQ(state.takeDueGrafts(T0 + 2s + 500ms).size(), 1u);
    EXPECT_TRUE(state.onNewMessage(key(2), A, true, T0 + 2s + 510ms).fullCopyTo.empty());
}

TEST(PlumtreeStateTest, AnnouncementFromUnknownLinkIsIgnored) {
    PlumtreeState state = withLinks({ A });
    state.onAnnouncement(B, { key(1) }, T0);
    EXPECT_EQ(state.missingCount(), 0u);
}
