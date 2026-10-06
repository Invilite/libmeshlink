// F7-b: hole punching coordination — codec of the 0xFF PUNCH_* messages and the state machines of R and both sides
#include <gtest/gtest.h>
#include "meshlink/hole_punch_coordinator.h"
#include "meshlink/hole_punch_participant.h"
#include "meshlink/hole_punch_policy.h"
#include "meshlink/hole_punch_wire.h"

using namespace invilite::Mesh;
using namespace std::chrono_literals;

namespace {

const auto T0 = std::chrono::steady_clock::time_point(std::chrono::seconds(1000));

PeerId peerId(uint8_t fill) { PeerId id; id.fill(fill); return id; }
HolePunchNonce nonceOf(uint8_t fill) { HolePunchNonce nonce; nonce.fill(fill); return nonce; }

// A is smaller than B, so A asks; R coordinates
const PeerId A = peerId(0x10), B = peerId(0x50), R = peerId(0x90), OTHER = peerId(0x70);
const HolePunchEndpoint EXT_A{ "203.0.113.7", 40001 }, EXT_B{ "2001:db8::42", 50002 };

template <typename Body> const Body& bodyAs(const HolePunchMessage& message) { return std::get<Body>(message.body); }

HolePunchBody roundTrip(const HolePunchBody& body) {
    const auto encoded = HolePunchCodec::encode(body);
    EXPECT_FALSE(encoded.payload.empty());
    const auto decoded = HolePunchCodec::decode(encoded.subtype, encoded.payload);
    EXPECT_TRUE(decoded.has_value());
    return decoded.value_or(body);
}

} // namespace

// ── codec ─────────────────────────────────────────────────────────────────────

TEST(HolePunchCodecTest, EveryMessageRoundTrips) {
    const auto request = std::get<HolePunchRequest>(roundTrip(HolePunchRequest{ B, nonceOf(1) }));
    EXPECT_EQ(request.target, B);
    EXPECT_EQ(request.nonce, nonceOf(1));

    const auto offer = std::get<HolePunchOffer>(roundTrip(HolePunchOffer{ A, nonceOf(2), EXT_A }));
    EXPECT_EQ(offer.initiator, A);
    EXPECT_EQ(offer.nonce, nonceOf(2));
    EXPECT_EQ(offer.initiatorEndpoint, EXT_A);

    EXPECT_EQ(std::get<HolePunchAccept>(roundTrip(HolePunchAccept{ nonceOf(3) })).nonce, nonceOf(3));

    const auto decline = std::get<HolePunchDecline>(roundTrip(HolePunchDecline{ nonceOf(4), HolePunchDeclineReason::PeerLeft }));
    EXPECT_EQ(decline.nonce, nonceOf(4));
    EXPECT_EQ(decline.reason, HolePunchDeclineReason::PeerLeft);

    const auto now = std::get<HolePunchNow>(roundTrip(HolePunchNow{ nonceOf(5), EXT_B }));
    EXPECT_EQ(now.nonce, nonceOf(5));
    EXPECT_EQ(now.remoteEndpoint, EXT_B);                                           // IPv6 too
}

TEST(HolePunchCodecTest, LayoutMatchesTheDocumentedWireFormat) {
    const auto encoded = HolePunchCodec::encode(HolePunchNow{ nonceOf(0xAB), { "1.2.3.4", 0x1F90 } });
    EXPECT_EQ(encoded.subtype, HolePunchSubtype::NOW);
    ASSERT_EQ(encoded.payload.size(), 16u + 1 + 4 + 2);
    EXPECT_EQ(encoded.payload[16], 4);                                              // family
    EXPECT_EQ(encoded.payload[17], 1);
    EXPECT_EQ(encoded.payload[20], 4);
    EXPECT_EQ(encoded.payload[21], 0x1F);                                           // port, big endian
    EXPECT_EQ(encoded.payload[22], 0x90);
    EXPECT_EQ(HolePunchCodec::encode(HolePunchRequest{ B, nonceOf(1) }).payload.size(), 48u);
}

TEST(HolePunchCodecTest, MalformedPayloadsAreRejected) {
    auto now = HolePunchCodec::encode(HolePunchNow{ nonceOf(1), EXT_A }).payload;
    auto truncated = now;
    truncated.pop_back();
    EXPECT_FALSE(HolePunchCodec::decode(HolePunchSubtype::NOW, truncated));
    auto extended = now;
    extended.push_back(0);
    EXPECT_FALSE(HolePunchCodec::decode(HolePunchSubtype::NOW, extended));
    auto unknownFamily = now;
    unknownFamily[16] = 5;
    EXPECT_FALSE(HolePunchCodec::decode(HolePunchSubtype::NOW, unknownFamily));

    auto decline = HolePunchCodec::encode(HolePunchDecline{ nonceOf(1), HolePunchDeclineReason::Busy }).payload;
    decline.back() = 0;
    EXPECT_FALSE(HolePunchCodec::decode(HolePunchSubtype::DECLINE, decline));
    decline.back() = 99;
    EXPECT_FALSE(HolePunchCodec::decode(HolePunchSubtype::DECLINE, decline));

    EXPECT_FALSE(HolePunchCodec::decode(HolePunchSubtype::ACCEPT, std::vector<uint8_t>(15)));
    EXPECT_FALSE(HolePunchCodec::decode(0x0065, std::vector<uint8_t>(16)));
    EXPECT_TRUE(HolePunchCodec::encode(HolePunchOffer{ A, nonceOf(1), { "not-an-ip", 1 } }).payload.empty());
}

// ── coordinator (R) ───────────────────────────────────────────────────────────

TEST(HolePunchCoordinatorTest, RequestBecomesOfferAndAcceptBecomesNowToBothSides) {
    HolePunchCoordinator coordinator;
    const auto offer = coordinator.onRequest(A, EXT_A, { B, nonceOf(1) }, EXT_B, T0);
    ASSERT_EQ(offer.size(), 1u);
    EXPECT_EQ(offer[0].peer, B);
    EXPECT_EQ(bodyAs<HolePunchOffer>(offer[0]).initiator, A);
    EXPECT_EQ(bodyAs<HolePunchOffer>(offer[0]).initiatorEndpoint, EXT_A);          // as R sees A, never declared by A

    const auto now = coordinator.onAccept(B, { nonceOf(1) }, T0 + 1s);
    ASSERT_EQ(now.size(), 2u);
    EXPECT_EQ(now[0].peer, A);
    EXPECT_EQ(bodyAs<HolePunchNow>(now[0]).remoteEndpoint, EXT_B);
    EXPECT_EQ(now[1].peer, B);
    EXPECT_EQ(bodyAs<HolePunchNow>(now[1]).remoteEndpoint, EXT_A);

    EXPECT_TRUE(coordinator.onAccept(B, { nonceOf(1) }, T0 + 1s).empty());          // once only
    EXPECT_TRUE(coordinator.onRequest(A, EXT_A, { B, nonceOf(1) }, EXT_B, T0 + 6s).empty());   // nonce remembered
    EXPECT_EQ(coordinator.openExchangeCount(), 0u);
}

TEST(HolePunchCoordinatorTest, AcceptCountsOnlyFromTheTargetAndBeforeTheDeadline) {
    HolePunchCoordinator coordinator;
    coordinator.onRequest(A, EXT_A, { B, nonceOf(1) }, EXT_B, T0);
    EXPECT_TRUE(coordinator.onAccept(A, { nonceOf(1) }, T0).empty());
    EXPECT_TRUE(coordinator.onAccept(OTHER, { nonceOf(1) }, T0).empty());
    EXPECT_TRUE(coordinator.onAccept(B, { nonceOf(2) }, T0).empty());
    EXPECT_TRUE(coordinator.onAccept(B, { nonceOf(1) }, T0 + 10s).empty());
}

TEST(HolePunchCoordinatorTest, DeclineOfTheTargetIsForwardedToTheRequester) {
    HolePunchCoordinator coordinator;
    coordinator.onRequest(A, EXT_A, { B, nonceOf(1) }, EXT_B, T0);
    const auto forwarded = coordinator.onDecline(B, { nonceOf(1), HolePunchDeclineReason::NoSlot }, T0);
    ASSERT_EQ(forwarded.size(), 1u);
    EXPECT_EQ(forwarded[0].peer, A);
    EXPECT_EQ(bodyAs<HolePunchDecline>(forwarded[0]).reason, HolePunchDeclineReason::NoSlot);
    EXPECT_TRUE(coordinator.onAccept(B, { nonceOf(1) }, T0).empty());
}

TEST(HolePunchCoordinatorTest, RequestsThatCannotBeCoordinatedAreDeclined) {
    HolePunchCoordinator coordinator;
    const auto reasonOf = [](const std::vector<HolePunchMessage>& out) {
        EXPECT_EQ(out.size(), 1u);
        return out.empty() ? HolePunchDeclineReason::NotAllowed : bodyAs<HolePunchDecline>(out[0]).reason;
    };
    EXPECT_EQ(reasonOf(coordinator.onRequest(A, EXT_A, { B, nonceOf(1) }, std::nullopt, T0)), HolePunchDeclineReason::NotNeighbor);
    EXPECT_EQ(reasonOf(coordinator.onRequest(A, EXT_A, { B, nonceOf(2) }, EXT_B, T0 + 4s)), HolePunchDeclineReason::RateLimited);
    EXPECT_EQ(reasonOf(coordinator.onRequest(B, EXT_B, { A, nonceOf(3) }, EXT_A, T0)), HolePunchDeclineReason::NotAllowed);   // larger asks
    EXPECT_EQ(coordinator.onRequest(A, EXT_A, { B, nonceOf(4) }, EXT_B, T0 + 5s).size(), 1u);
    EXPECT_EQ(coordinator.openExchangeCount(), 1u);
    // We dialed the requester: its source port is its listening port, not a NAT mapping a punch could reuse
    EXPECT_EQ(reasonOf(coordinator.onRequest(peerId(0x01), std::nullopt, { B, nonceOf(5) }, EXT_B, T0)), HolePunchDeclineReason::NotAllowed);
}

TEST(HolePunchCoordinatorTest, PairAtOnePublicAddressIsToldToUseLocalAddresses) {
    HolePunchCoordinator coordinator;
    const auto out = coordinator.onRequest(A, EXT_A, { B, nonceOf(1) }, HolePunchEndpoint{ EXT_A.address, 40999 }, T0);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].peer, A);
    EXPECT_EQ(bodyAs<HolePunchDecline>(out[0]).reason, HolePunchDeclineReason::SameNetwork);
    EXPECT_EQ(coordinator.openExchangeCount(), 0u);
}

TEST(HolePunchCoordinatorTest, OpenExchangesAreBounded) {
    HolePunchCoordinator coordinator({ 10s, 5s, 2 });
    EXPECT_TRUE(std::holds_alternative<HolePunchOffer>(coordinator.onRequest(peerId(1), EXT_A, { B, nonceOf(1) }, EXT_B, T0)[0].body));
    EXPECT_TRUE(std::holds_alternative<HolePunchOffer>(coordinator.onRequest(peerId(2), EXT_A, { B, nonceOf(2) }, EXT_B, T0)[0].body));
    const auto third = coordinator.onRequest(peerId(3), EXT_A, { B, nonceOf(3) }, EXT_B, T0);
    EXPECT_EQ(bodyAs<HolePunchDecline>(third[0]).reason, HolePunchDeclineReason::RateLimited);
    coordinator.expire(T0 + 10s);
    EXPECT_EQ(coordinator.openExchangeCount(), 0u);
}

TEST(HolePunchCoordinatorTest, LostNeighborEndsItsExchangesWithPeerLeft) {
    HolePunchCoordinator coordinator;
    coordinator.onRequest(A, EXT_A, { B, nonceOf(1) }, EXT_B, T0);
    const auto out = coordinator.onNeighborLost(B);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].peer, A);
    EXPECT_EQ(bodyAs<HolePunchDecline>(out[0]).reason, HolePunchDeclineReason::PeerLeft);
    EXPECT_TRUE(coordinator.onAccept(B, { nonceOf(1) }, T0).empty());
}

// ── participant (A and B) ─────────────────────────────────────────────────────

TEST(HolePunchParticipantTest, FullExchangeStartsOnePunchOnEachSide) {
    HolePunchParticipant a(A), b(B);
    const auto request = a.request(B, R, nonceOf(1), T0);
    ASSERT_TRUE(request);
    EXPECT_EQ(request->peer, R);
    EXPECT_TRUE(a.isExchangingWith(B));

    const auto answer = b.onOffer(R, { A, nonceOf(1), EXT_A }, std::nullopt, T0);
    ASSERT_TRUE(answer);
    EXPECT_EQ(answer->peer, R);
    EXPECT_TRUE(std::holds_alternative<HolePunchAccept>(answer->body));

    const auto startA = a.onNow(R, { nonceOf(1), EXT_B }, T0 + 1s);
    const auto startB = b.onNow(R, { nonceOf(1), EXT_A }, T0 + 1s);
    ASSERT_TRUE(startA);
    ASSERT_TRUE(startB);
    EXPECT_EQ(startA->peer, B);
    EXPECT_EQ(startA->remoteEndpoint, EXT_B);
    EXPECT_TRUE(startA->initiatesHandshake);                                        // the asking side, the smaller PeerId
    EXPECT_FALSE(startB->initiatesHandshake);
    EXPECT_EQ(startA->deadline, T0 + 5s);

    EXPECT_FALSE(a.onNow(R, { nonceOf(1), EXT_B }, T0 + 1s));                       // replayed NOW starts nothing
    EXPECT_TRUE(a.isExchangingWith(B));
    a.finishPunch(B, true, T0 + 2s);
    EXPECT_FALSE(a.isExchangingWith(B));
}

TEST(HolePunchParticipantTest, NowStartsNothingUnlessAgreedWithThatNeighbor) {
    HolePunchParticipant a(A);
    a.request(B, R, nonceOf(1), T0);
    EXPECT_FALSE(a.onNow(OTHER, { nonceOf(1), EXT_B }, T0));                        // another neighbor
    EXPECT_FALSE(a.onNow(R, { nonceOf(2), EXT_B }, T0));                            // unknown nonce
    EXPECT_FALSE(a.onNow(R, { nonceOf(1), EXT_B }, T0 + 10s));                      // too late
}

TEST(HolePunchParticipantTest, OnlyTheSmallerPeerIdAsksAndOneExchangePerPeer) {
    HolePunchParticipant b(B), a(A);
    EXPECT_FALSE(b.request(A, R, nonceOf(1), T0));
    EXPECT_TRUE(a.request(B, R, nonceOf(2), T0));
    EXPECT_FALSE(a.request(B, OTHER, nonceOf(3), T0));
}

TEST(HolePunchParticipantTest, OfferIsDeclinedForRuleBusyOrLocalObstacle) {
    HolePunchParticipant b(B), a(A);
    const auto reasonOf = [](const std::optional<HolePunchMessage>& out) { return std::get<HolePunchDecline>(out->body).reason; };

    EXPECT_EQ(reasonOf(a.onOffer(R, { B, nonceOf(1), EXT_B }, std::nullopt, T0)), HolePunchDeclineReason::NotAllowed);
    EXPECT_EQ(reasonOf(b.onOffer(R, { A, nonceOf(2), EXT_A }, HolePunchDeclineReason::NoSlot, T0)), HolePunchDeclineReason::NoSlot);
    ASSERT_TRUE(std::holds_alternative<HolePunchAccept>(b.onOffer(R, { A, nonceOf(3), EXT_A }, std::nullopt, T0)->body));
    EXPECT_EQ(reasonOf(b.onOffer(OTHER, { A, nonceOf(4), EXT_A }, std::nullopt, T0)), HolePunchDeclineReason::Busy);
    EXPECT_FALSE(b.onOffer(R, { A, nonceOf(3), EXT_A }, std::nullopt, T0));       // replay: no second answer
}

TEST(HolePunchParticipantTest, DeclineTimeoutAndLostNeighborEndTheExchange) {
    HolePunchParticipant a(A);
    a.request(B, R, nonceOf(1), T0);
    EXPECT_FALSE(a.onDecline(OTHER, { nonceOf(1), HolePunchDeclineReason::NoSlot }, T0));
    const auto declined = a.onDecline(R, { nonceOf(1), HolePunchDeclineReason::NoSlot }, T0);
    ASSERT_TRUE(declined);
    EXPECT_EQ(declined->peer, B);
    EXPECT_EQ(declined->reason, HolePunchDeclineReason::NoSlot);
    EXPECT_FALSE(a.isExchangingWith(B));

    a.request(B, R, nonceOf(2), T0);
    EXPECT_TRUE(a.expire(T0 + 9s).empty());
    const auto timedOut = a.expire(T0 + 10s);
    ASSERT_EQ(timedOut.size(), 1u);
    EXPECT_FALSE(timedOut[0].reason.has_value());

    a.request(B, R, nonceOf(3), T0 + 10s);
    const auto lost = a.onNeighborLost(R);
    ASSERT_EQ(lost.size(), 1u);
    EXPECT_EQ(lost[0].reason, HolePunchDeclineReason::PeerLeft);
    EXPECT_FALSE(a.onNow(R, { nonceOf(3), EXT_B }, T0 + 10s));
}

TEST(HolePunchParticipantTest, PunchingExchangeIsNotEndedByItsCoordinatorLeaving) {
    HolePunchParticipant a(A);
    a.request(B, R, nonceOf(1), T0);
    ASSERT_TRUE(a.onNow(R, { nonceOf(1), EXT_B }, T0));
    EXPECT_TRUE(a.onNeighborLost(R).empty());                                       // R's job is done once NOW arrived
    EXPECT_TRUE(a.expire(T0 + 4s).empty());                                         // the punch reports its own outcome
    EXPECT_FALSE(a.isExchangingWith(B));
}

TEST(HolePunchParticipantTest, FailedPunchesRestThePairWithGrowingPauses) {
    HolePunchParticipant a(A, { 10s, 4s, { 30s, 60s } }), b(B, { 10s, 4s, { 30s, 60s } });
    a.request(B, R, nonceOf(1), T0);
    ASSERT_TRUE(a.onNow(R, { nonceOf(1), EXT_B }, T0));
    a.finishPunch(B, false, T0 + 4s);
    EXPECT_TRUE(a.isResting(B, T0 + 33s));
    EXPECT_FALSE(a.request(B, R, nonceOf(2), T0 + 33s));
    EXPECT_FALSE(a.isResting(B, T0 + 34s));

    a.recordFailedAttempt(B, T0 + 34s);                                             // second failure: the longest pause, and it repeats
    a.recordFailedAttempt(B, T0 + 100s);
    EXPECT_TRUE(a.isResting(B, T0 + 159s));
    EXPECT_FALSE(a.isResting(B, T0 + 160s));

    ASSERT_TRUE(a.request(B, R, nonceOf(3), T0 + 160s));
    ASSERT_TRUE(a.onNow(R, { nonceOf(3), EXT_B }, T0 + 160s));
    a.finishPunch(B, true, T0 + 161s);                                              // success forgets the failures
    EXPECT_FALSE(a.isResting(B, T0 + 161s));

    b.recordFailedAttempt(A, T0);
    const auto answer = b.onOffer(R, { A, nonceOf(9), EXT_A }, std::nullopt, T0 + 1s);
    EXPECT_EQ(std::get<HolePunchDecline>(answer->body).reason, HolePunchDeclineReason::TooManyAttempts);
}

// ── policy ────────────────────────────────────────────────────────────────────

TEST(HolePunchPolicyTest, PrivateLinksFirstThenTopologyGapFreshestRecordFirst) {
    const auto now = std::chrono::system_clock::now();
    HolePunchSituation situation;
    situation.behindNat      = true;
    situation.outboundTarget = 4;
    situation.candidates     = { { B, now - 1h }, { OTHER, now - 1min }, { R, now - 2h } };

    EXPECT_EQ(chooseHolePunchTarget(situation, 2), OTHER);                         // (c): no private link yet

    situation.privateLinks           = 2;
    situation.outboundConnections    = 2;
    situation.dialableCandidatesLeft = true;
    EXPECT_FALSE(chooseHolePunchTarget(situation, 2));                             // Topology can still dial someone
    situation.dialableCandidatesLeft = false;
    EXPECT_EQ(chooseHolePunchTarget(situation, 2), OTHER);                         // (a): below target, nothing dialable
    situation.outboundConnections = 4;
    EXPECT_FALSE(chooseHolePunchTarget(situation, 2));                             // target met

    situation.privateLinks = 0;
    situation.behindNat    = false;                                                 // everyone can dial us — no punching
    EXPECT_FALSE(chooseHolePunchTarget(situation, 2));
    situation.behindNat  = true;
    situation.candidates.clear();
    EXPECT_FALSE(chooseHolePunchTarget(situation, 2));
}
