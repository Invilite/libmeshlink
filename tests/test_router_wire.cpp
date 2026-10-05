#include <gtest/gtest.h>
#include "meshlink/identity.h"
#include "meshlink/router_wire.h"

#include <functional>

using namespace invilite::Mesh;
using namespace std::chrono_literals;

namespace {

const auto NOW = std::chrono::system_clock::time_point(std::chrono::seconds(1'800'000'000));
const uint32_t NOW_SECONDS = 1'800'000'000;

PeerId peerId(uint8_t fill) { PeerId id; id.fill(fill); return id; }

// Network splits Group and Subtype off the frame before the Router sees it — mirror that
RoutedMessageStatus decodeFrame(const std::vector<uint8_t>& frame, RoutedMessage& out, std::chrono::system_clock::time_point now = NOW) {
    if (frame.size() < 3) return RoutedMessageStatus::MalformedEncoding;
    const uint16_t subtype = static_cast<uint16_t>(frame[1] << 8 | frame[2]);
    return RouterWire::decode(frame[0], subtype, std::span<const uint8_t>(frame).subspan(3), now, out);
}

void signWith(RoutedMessage& message, const LocalIdentity& identity) {
    message.signature = identity.sign(RouterWire::bytesToSign(message));
}

// What a routed message carries: application data, or one of the Router's own routed messages (Group 0xFE)
enum class Content { Data, Ack, RouteError };

// A valid message of the given mode / content with every optional part the mode requires; signed when required
RoutedMessage makeMessage(const LocalIdentity& sender, RoutingMode mode, Content content) {
    RoutedMessage m;
    m.group             = content == Content::Data ? 0x12 : RouterWire::ROUTER_PROTOCOL_GROUP;
    m.subtype           = content == Content::Data ? 0xABCD : content == Content::Ack ? RouterWire::SUBTYPE_ACK : RouterWire::SUBTYPE_ROUTE_ERROR;
    m.mode              = mode;
    m.ttlInitial        = 16;
    m.ttlRemaining      = 13;
    m.msgId             = 0x0102030405060708ULL;
    m.sentAtUnixSeconds = NOW_SECONDS;
    m.sender            = sender.getPeerId();
    if (!RouterWire::reachesEveryNode(mode)) m.destination = peerId(0xDD);
    if (mode == RoutingMode::Routed)         m.sourceRoute = SourceRoute{ 1, { peerId(0xA1), peerId(0xA2), peerId(0xA3) } };
    if (content == Content::Ack)             m.payload = RouterWire::encodeAckPayload({ 0x1111 });
    else if (content == Content::RouteError) m.payload = RouterWire::encodeRouteErrorPayload({ 0x2222, peerId(0xC1), RouteErrorReason::NextHopNotNeighbor });
    else                                     m.payload = { 'h', 'e', 'l', 'l', 'o' };
    if (RouterWire::requiresSignature(m.group, mode)) signWith(m, sender);
    return m;
}

// Encode, decode and return the decoded message (fails the test on any error)
RoutedMessage roundTrip(const RoutedMessage& message) {
    const auto frame = RouterWire::encode(message);
    EXPECT_FALSE(frame.empty());
    RoutedMessage decoded;
    EXPECT_EQ(decodeFrame(frame, decoded), RoutedMessageStatus::Success);
    return decoded;
}

const RoutingMode ALL_MODES[] = { RoutingMode::Flood, RoutingMode::Broadcast, RoutingMode::Routed, RoutingMode::Unicast };
const Content ALL_CONTENTS[] = { Content::Data, Content::Ack, Content::RouteError };

// Offsets inside an encoded frame (Group | Subtype precede the routing header)
constexpr size_t VERSION_MODE_OFFSET = 3;
constexpr size_t FLAGS_OFFSET        = 4;
constexpr size_t TTL_REMAINING_OFFSET = 5;
constexpr size_t TTL_INITIAL_OFFSET  = 6;
constexpr size_t SENT_AT_OFFSET      = 15;
constexpr size_t AFTER_FIXED_OFFSET  = 3 + RouterWire::FIXED_HEADER_SIZE;

} // namespace

// ── Round trip ──────────────────────────────────────────────────────────────

TEST(RouterWireTest, RoundTripEveryModeContentAndFlagCombination) {
    const auto sender = LocalIdentity::generate();
    for (const RoutingMode mode : ALL_MODES) {
        for (const Content content : ALL_CONTENTS) {
            if (RouterWire::reachesEveryNode(mode) && content != Content::Data) continue;
            for (const bool ackRequested : { false, true }) {                                  // allowed in every mode: every addressee answers
                for (const bool withExtensions : { false, true }) {
                    SCOPED_TRACE(testing::Message() << "mode=" << int(mode) << " content=" << int(content) << " ack=" << ackRequested << " ext=" << withExtensions);
                    RoutedMessage m = makeMessage(sender, mode, content);
                    m.ackRequested = ackRequested;
                    if (withExtensions) m.extensions = { { 0x05, { 1, 2, 3 } }, { RouterWire::EXTENSION_SENT_TO, { 0xFF, 0x00 } } };
                    if (RouterWire::requiresSignature(m.group, mode)) signWith(m, sender);

                    const RoutedMessage decoded = roundTrip(m);
                    EXPECT_EQ(decoded, m);
                    if (RouterWire::requiresSignature(m.group, mode)) { EXPECT_TRUE(RouterWire::verifySignature(decoded, sender.getEd25519Pub())); }
                }
            }
        }
    }
}

TEST(RouterWireTest, RoundTripEmptyPayloadAndEmptyRoute) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::Routed, Content::Data);
    m.payload.clear();
    m.sourceRoute = SourceRoute{ 0, {} };
    EXPECT_EQ(roundTrip(m), m);
}

TEST(RouterWireTest, RoundTripMaximalRouteAndExtensionLengths) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::Routed, Content::Data);
    m.sourceRoute = SourceRoute{ 255, std::vector<PeerId>(255, peerId(0x01)) };
    m.extensions = { { 0x07, std::vector<uint8_t>(0xFFFF - 3, 0x5A) } };                     // fills the 2-byte block length exactly
    EXPECT_EQ(roundTrip(m), m);
}

// Bit and value positions from docs/router.md 3.4
TEST(RouterWireTest, ModeAndFlagsSitWhereTheDesignSays) {
    const auto sender = LocalIdentity::generate();
    const std::pair<RoutingMode, uint8_t> modes[] = { { RoutingMode::Flood, 0x0 }, { RoutingMode::Broadcast, 0x1 }, { RoutingMode::Routed, 0x2 }, { RoutingMode::Unicast, 0x3 } };
    for (const auto& [mode, value] : modes) {
        EXPECT_EQ(RouterWire::encode(makeMessage(sender, mode, Content::Data))[VERSION_MODE_OFFSET], 0x10 | value) << "mode " << int(value);
    }

    RoutedMessage m = makeMessage(sender, RoutingMode::Unicast, Content::Data);
    EXPECT_EQ(RouterWire::encode(m)[FLAGS_OFFSET], 0x00);
    m.ackRequested = true;
    EXPECT_EQ(RouterWire::encode(m)[FLAGS_OFFSET], 0x01);                                    // bit 0 ACK_REQUESTED
    m.ackRequested = false;
    m.extensions = { { 0x05, { 1 } } };
    EXPECT_EQ(RouterWire::encode(m)[FLAGS_OFFSET], 0x02);                                    // bit 1 HAS_EXTENSIONS
}

// Overhead table in docs/router.md 3.5 (Network header + routing header, without the payload)
TEST(RouterWireTest, EncodedOverheadMatchesDesign) {
    const auto sender = LocalIdentity::generate();
    auto overhead = [](RoutedMessage m) { m.payload.clear(); if (!m.signature.empty()) m.signature.assign(64, 0); return RouterWire::encode(m).size(); };

    EXPECT_EQ(overhead(makeMessage(sender, RoutingMode::Broadcast, Content::Data)), 115u);
    EXPECT_EQ(overhead(makeMessage(sender, RoutingMode::Flood, Content::Data)), 115u);
    EXPECT_EQ(overhead(makeMessage(sender, RoutingMode::Unicast, Content::Data)), 83u);

    RoutedMessage routed = makeMessage(sender, RoutingMode::Routed, Content::Data);
    routed.sourceRoute = SourceRoute{ 0, std::vector<PeerId>(5, peerId(0x01)) };
    EXPECT_EQ(overhead(routed), 245u);

    EXPECT_EQ(RouterWire::encode(makeMessage(sender, RoutingMode::Unicast, Content::Ack)).size(), 155u);   // whole ACK frame
}

TEST(RouterWireTest, UnknownExtensionsAndReservedFlagBitsSurviveRoundTrip) {
    const auto sender = LocalIdentity::generate();
    for (const Content content : { Content::Data, Content::Ack }) {
        RoutedMessage m = makeMessage(sender, content == Content::Data ? RoutingMode::Broadcast : RoutingMode::Unicast, content);
        m.reservedFlagBits = 0xFC;                                                          // a future sender sets every reserved bit
        m.extensions = { { 0x3E, { 9 } }, { 0x7E, { 8 } } };                                // unknown signed + unknown per-hop, both non-critical
        signWith(m, sender);

        const RoutedMessage decoded = roundTrip(m);
        EXPECT_EQ(decoded, m);
        EXPECT_TRUE(RouterWire::verifySignature(decoded, sender.getEd25519Pub()));         // a relay re-encoding it does not break the signature
        EXPECT_TRUE(RouterWire::verifySignature(roundTrip(decoded), sender.getEd25519Pub()));
    }
}

TEST(RouterWireTest, RouterMessagePayloadsRoundTrip) {
    AckPayload decodedAck;
    ASSERT_TRUE(RouterWire::decodeAckPayload(RouterWire::encodeAckPayload({ 0xDEADBEEFCAFEF00DULL }), decodedAck));
    EXPECT_EQ(decodedAck.acknowledgedMsgId, 0xDEADBEEFCAFEF00DULL);

    const RouteErrorPayload error{ 42, peerId(7), static_cast<RouteErrorReason>(0x77) };   // unknown reason is kept
    RouteErrorPayload decodedError;
    ASSERT_TRUE(RouterWire::decodeRouteErrorPayload(RouterWire::encodeRouteErrorPayload(error), decodedError));
    EXPECT_EQ(decodedError, error);
}

TEST(RouterWireTest, RouterMessagePayloadDecodersRequireExactLength) {
    auto ack = RouterWire::encodeAckPayload({ 1 });
    ASSERT_EQ(ack.size(), 8u);
    AckPayload decodedAck;
    ack.push_back(0);
    EXPECT_FALSE(RouterWire::decodeAckPayload(ack, decodedAck));
    ack.resize(7);
    EXPECT_FALSE(RouterWire::decodeAckPayload(ack, decodedAck));

    auto error = RouterWire::encodeRouteErrorPayload({ 1, peerId(1), RouteErrorReason::NextHopSendRefused });
    RouteErrorPayload decodedError;
    error.push_back(0);
    EXPECT_FALSE(RouterWire::decodeRouteErrorPayload(error, decodedError));
    error.resize(error.size() - 2);
    EXPECT_FALSE(RouterWire::decodeRouteErrorPayload(error, decodedError));
}

// ── Encode refuses inconsistent messages ────────────────────────────────────

TEST(RouterWireTest, EncodeRefusesInconsistentMessages) {
    const auto sender = LocalIdentity::generate();
    const RoutedMessage unicast   = makeMessage(sender, RoutingMode::Unicast, Content::Data);
    const RoutedMessage broadcast = makeMessage(sender, RoutingMode::Broadcast, Content::Data);
    const RoutedMessage flood     = makeMessage(sender, RoutingMode::Flood, Content::Data);
    const RoutedMessage routed    = makeMessage(sender, RoutingMode::Routed, Content::Data);
    const RoutedMessage ack       = makeMessage(sender, RoutingMode::Unicast, Content::Ack);
    for (const auto* m : { &unicast, &broadcast, &flood, &routed, &ack }) ASSERT_FALSE(RouterWire::encode(*m).empty());

    auto refused = [](RoutedMessage m, auto change) { change(m); return RouterWire::encode(m).empty(); };
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.group = 0xFF; }));
    EXPECT_TRUE(refused(ack,       [](RoutedMessage& m) { m.subtype = RouterWire::SUBTYPE_IHAVE; }));      // neighbor-only: no routing header
    EXPECT_TRUE(refused(ack,       [](RoutedMessage& m) { m.subtype = 0x0200; }));
    EXPECT_TRUE(refused(ack,       [](RoutedMessage& m) { m.mode = RoutingMode::Broadcast; m.destination.reset(); }));   // Router messages are point-to-point
    EXPECT_TRUE(refused(ack,       [](RoutedMessage& m) { m.mode = RoutingMode::Flood; m.destination.reset(); }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.mode = static_cast<RoutingMode>(4); }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.reservedFlagBits = 0x01; }));    // ACK_REQUESTED, not reserved
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.reservedFlagBits = 0x02; }));    // HAS_EXTENSIONS, not reserved
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.ttlInitial = 0; m.ttlRemaining = 0; }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.ttlRemaining = m.ttlInitial + 1; }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.destination.reset(); }));
    EXPECT_TRUE(refused(broadcast, [](RoutedMessage& m) { m.destination = peerId(1); }));
    EXPECT_TRUE(refused(flood,     [](RoutedMessage& m) { m.destination = peerId(1); }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.sourceRoute = SourceRoute{}; }));
    EXPECT_TRUE(refused(routed,    [](RoutedMessage& m) { m.sourceRoute.reset(); }));
    EXPECT_TRUE(refused(routed,    [](RoutedMessage& m) { m.sourceRoute->nextHopIndex = 4; }));
    EXPECT_TRUE(refused(routed,    [](RoutedMessage& m) { m.sourceRoute->hops.resize(256); m.sourceRoute->nextHopIndex = 0; }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.extensions = { { 1, std::vector<uint8_t>(0x10000) } }; }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.extensions = { { 1, std::vector<uint8_t>(0x8000) }, { 2, std::vector<uint8_t>(0x8000) } }; }));
    EXPECT_TRUE(refused(broadcast, [](RoutedMessage& m) { m.signature.clear(); }));             // signature required
    EXPECT_TRUE(refused(flood,     [](RoutedMessage& m) { m.signature.clear(); }));
    EXPECT_TRUE(refused(ack,       [](RoutedMessage& m) { m.signature.clear(); }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.signature.assign(64, 0); }));       // application UNICAST data carries none
}

// ── Receive validation (docs/router.md 3.6) — each rule rejects ─────────────

TEST(RouterWireTest, OnlyFramesWithRoutingHeaderAreDecoded) {
    const auto sender = LocalIdentity::generate();
    const auto dataFrame = RouterWire::encode(makeMessage(sender, RoutingMode::Unicast, Content::Data));
    const auto ackFrame  = RouterWire::encode(makeMessage(sender, RoutingMode::Unicast, Content::Ack));
    const auto dataBody  = std::span<const uint8_t>(dataFrame).subspan(3);
    const auto ackBody   = std::span<const uint8_t>(ackFrame).subspan(3);
    RoutedMessage out;

    for (const uint16_t subtype : { uint16_t(0x0000), uint16_t(0x0100), uint16_t(0xFFFF) }) {
        EXPECT_EQ(RouterWire::decode(0xFF, subtype, ackBody, NOW, out), RoutedMessageStatus::NotRoutedGroup);
    }
    for (const uint16_t subtype : { uint16_t(0x0000), RouterWire::SUBTYPE_IHAVE, uint16_t(0x00FF), uint16_t(0x0200) }) {
        EXPECT_EQ(RouterWire::decode(0xFE, subtype, ackBody, NOW, out), RoutedMessageStatus::NotRoutedGroup) << "subtype " << subtype;
    }
    EXPECT_EQ(RouterWire::decode(0xFE, RouterWire::LAST_ROUTED_ROUTER_SUBTYPE, ackBody, NOW, out), RoutedMessageStatus::Success);   // unknown routed subtype: header still valid
    EXPECT_EQ(RouterWire::decode(0xFD, 0, dataBody, NOW, out), RoutedMessageStatus::Success);
}

TEST(RouterWireTest, RejectsHeaderFieldViolations) {
    const auto sender = LocalIdentity::generate();
    const auto unicast = RouterWire::encode(makeMessage(sender, RoutingMode::Unicast, Content::Data));
    const auto ack     = RouterWire::encode(makeMessage(sender, RoutingMode::Unicast, Content::Ack));

    auto statusAfter = [](std::vector<uint8_t> frame, auto change) { change(frame); RoutedMessage out; return decodeFrame(frame, out); };

    EXPECT_EQ(statusAfter(unicast, [](auto& f) { f[VERSION_MODE_OFFSET] = 0x23; }), RoutedMessageStatus::UnsupportedVersion);
    EXPECT_EQ(statusAfter(unicast, [](auto& f) { f[VERSION_MODE_OFFSET] = 0x03; }), RoutedMessageStatus::UnsupportedVersion);
    for (uint8_t mode = 4; mode <= 0xF; ++mode) {
        EXPECT_EQ(statusAfter(unicast, [mode](auto& f) { f[VERSION_MODE_OFFSET] = 0x10 | mode; }), RoutedMessageStatus::UnknownMode);
    }
    // Router messages never travel to every node (the destination bytes would then be read as signature)
    EXPECT_EQ(statusAfter(ack, [](auto& f) { f[VERSION_MODE_OFFSET] = 0x10; }), RoutedMessageStatus::RouterMessageToEveryNode);
    EXPECT_EQ(statusAfter(ack, [](auto& f) { f[VERSION_MODE_OFFSET] = 0x11; }), RoutedMessageStatus::RouterMessageToEveryNode);
    EXPECT_EQ(statusAfter(unicast, [](auto& f) { f[TTL_INITIAL_OFFSET] = 0; f[TTL_REMAINING_OFFSET] = 0; }), RoutedMessageStatus::InvalidTtl);
    EXPECT_EQ(statusAfter(unicast, [](auto& f) { f[TTL_REMAINING_OFFSET] = f[TTL_INITIAL_OFFSET] + 1; }), RoutedMessageStatus::InvalidTtl);
    EXPECT_EQ(statusAfter(unicast, [](auto& f) { f[TTL_REMAINING_OFFSET] = 0; }), RoutedMessageStatus::Success);   // TTL used up: deliver, do not forward
}

// The neighbor is told about a mode it sent that we do not know: the fixed header must be readable
TEST(RouterWireTest, UnknownModeStillYieldsFixedHeader) {
    const auto sender = LocalIdentity::generate();
    auto frame = RouterWire::encode(makeMessage(sender, RoutingMode::Broadcast, Content::Data));
    frame[VERSION_MODE_OFFSET] = 0x1A;
    RoutedMessage out;
    ASSERT_EQ(decodeFrame(frame, out), RoutedMessageStatus::UnknownMode);
    EXPECT_EQ(static_cast<uint8_t>(out.mode), 0xA);
    EXPECT_EQ(out.sender, sender.getPeerId());
    EXPECT_EQ(out.msgId, 0x0102030405060708ULL);
}

TEST(RouterWireTest, RejectsTimestampOutsideWindow) {
    const auto frame = RouterWire::encode(makeMessage(LocalIdentity::generate(), RoutingMode::Unicast, Content::Data));
    RoutedMessage out;
    EXPECT_EQ(decodeFrame(frame, out, NOW + 5min), RoutedMessageStatus::Success);
    EXPECT_EQ(decodeFrame(frame, out, NOW - 5min), RoutedMessageStatus::Success);
    EXPECT_EQ(decodeFrame(frame, out, NOW + 5min + 1s), RoutedMessageStatus::TimestampOutOfWindow);   // message too old
    EXPECT_EQ(decodeFrame(frame, out, NOW - 5min - 1s), RoutedMessageStatus::TimestampOutOfWindow);   // message from the future
}

TEST(RouterWireTest, RejectsSourceRouteIndexPastRoute) {
    auto frame = RouterWire::encode(makeMessage(LocalIdentity::generate(), RoutingMode::Routed, Content::Data));
    const size_t indexOffset = AFTER_FIXED_OFFSET + 32 + 1;                                  // after destination and hop count (3)
    RoutedMessage out;
    frame[indexOffset] = 3;
    EXPECT_EQ(decodeFrame(frame, out), RoutedMessageStatus::Success);                        // route used up, destination is next
    frame[indexOffset] = 4;
    EXPECT_EQ(decodeFrame(frame, out), RoutedMessageStatus::SourceRouteIndexOutOfRange);
}

TEST(RouterWireTest, RejectsUnknownCriticalExtensionButKeepsUnknownNonCritical) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::Unicast, Content::Data);
    RoutedMessage out;

    m.extensions = { { 0x3F, { 1 } } };
    EXPECT_EQ(decodeFrame(RouterWire::encode(m), out), RoutedMessageStatus::Success);
    EXPECT_EQ(out.extensions, m.extensions);

    m.extensions = { { 0x3F, { 1 } }, { 0x81, { 2 } } };                                    // critical, signed
    EXPECT_EQ(decodeFrame(RouterWire::encode(m), out), RoutedMessageStatus::UnknownCriticalExtension);
    m.extensions = { { 0xC1, { 2 } } };                                                      // critical, per-hop
    EXPECT_EQ(decodeFrame(RouterWire::encode(m), out), RoutedMessageStatus::UnknownCriticalExtension);
}

// Every truncation must fail. ACK payload has an exact length, so even cuts inside the payload are detected.
TEST(RouterWireTest, RejectsEveryTruncation) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::Routed, Content::Ack);
    m.extensions = { { 0x05, { 1, 2, 3 } } };
    signWith(m, sender);
    const auto frame = RouterWire::encode(m);

    for (size_t length = 3; length < frame.size(); ++length) {
        const std::vector<uint8_t> truncated(frame.begin(), frame.begin() + length);
        RoutedMessage out;
        EXPECT_EQ(decodeFrame(truncated, out), RoutedMessageStatus::MalformedEncoding) << "length " << length;
    }
}

TEST(RouterWireTest, RejectsLengthFieldsBeyondFrame) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage out;

    // Source route claims more hops than the frame holds
    RoutedMessage routed = makeMessage(sender, RoutingMode::Routed, Content::Data);
    routed.payload.clear();
    auto frame = RouterWire::encode(routed);
    frame[AFTER_FIXED_OFFSET + 32] = 4;
    EXPECT_EQ(decodeFrame(frame, out), RoutedMessageStatus::MalformedEncoding);

    // Extension block longer than the rest of the frame
    RoutedMessage extended = makeMessage(sender, RoutingMode::Unicast, Content::Data);
    extended.extensions = { { 0x05, { 1, 2, 3 } } };
    extended.payload.clear();
    frame = RouterWire::encode(extended);
    const size_t blockLengthOffset = AFTER_FIXED_OFFSET + 32;
    frame[blockLengthOffset + 1] = 7;                                                        // 6 bytes follow
    EXPECT_EQ(decodeFrame(frame, out), RoutedMessageStatus::MalformedEncoding);

    // A TLV crossing the declared end of the extension block (payload follows, so the bytes exist)
    extended.payload = { 9, 9, 9, 9 };
    frame = RouterWire::encode(extended);
    frame[blockLengthOffset + 1] = 5;                                                        // block ends inside the TLV value
    EXPECT_EQ(decodeFrame(frame, out), RoutedMessageStatus::MalformedEncoding);

    // HAS_EXTENSIONS set but no block at all
    RoutedMessage plain = makeMessage(sender, RoutingMode::Unicast, Content::Data);
    plain.payload.clear();
    frame = RouterWire::encode(plain);
    frame[FLAGS_OFFSET] |= 0x02;
    EXPECT_EQ(decodeFrame(frame, out), RoutedMessageStatus::MalformedEncoding);
}

TEST(RouterWireTest, RejectsMalformedRouterMessagePayloads) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage out;
    for (const Content content : { Content::Ack, Content::RouteError }) {
        RoutedMessage m = makeMessage(sender, RoutingMode::Unicast, content);
        m.payload.push_back(0);                                                              // trailing byte
        signWith(m, sender);
        EXPECT_EQ(decodeFrame(RouterWire::encode(m), out), RoutedMessageStatus::MalformedEncoding);
    }
}

// ── Signature: [M] fields may change, [S] fields may not ────────────────────

TEST(RouterWireTest, RelayMutableFieldsDoNotBreakSignature) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::Routed, Content::Ack);
    m.extensions = { { 0x05, { 1 } }, { RouterWire::EXTENSION_SENT_TO, { 0xAA } } };
    signWith(m, sender);

    const std::vector<std::function<void(RoutedMessage&)>> relayChanges = {
        [](RoutedMessage& r) { r.ttlRemaining -= 1; },
        [](RoutedMessage& r) { r.sourceRoute->nextHopIndex += 1; },
        [](RoutedMessage& r) { r.extensions[1].value = { 0xBB, 0xCC }; },                   // relay replaces its per-hop SENT_TO
        [](RoutedMessage& r) { r.extensions.erase(r.extensions.begin() + 1); },              // per-hop removed
        [](RoutedMessage& r) { r.extensions.push_back({ 0x7A, { 1 } }); },                   // per-hop added
    };
    for (size_t i = 0; i < relayChanges.size(); ++i) {
        RoutedMessage relayed = roundTrip(m);
        relayChanges[i](relayed);
        EXPECT_TRUE(RouterWire::verifySignature(roundTrip(relayed), sender.getEd25519Pub())) << "relay change " << i;
    }

    // Broadcast with no extensions: a relay adding a per-hop extension flips the unsigned HAS_EXTENSIONS bit
    RoutedMessage broadcast = makeMessage(sender, RoutingMode::Broadcast, Content::Data);
    broadcast.extensions.push_back({ RouterWire::EXTENSION_SENT_TO, { 0x01 } });
    EXPECT_TRUE(RouterWire::verifySignature(roundTrip(broadcast), sender.getEd25519Pub()));
}

TEST(RouterWireTest, SignedFieldChangesBreakSignature) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::Routed, Content::Ack);
    m.extensions = { { 0x05, { 1 } }, { RouterWire::EXTENSION_SENT_TO, { 0xAA } } };
    signWith(m, sender);
    ASSERT_TRUE(RouterWire::verifySignature(m, sender.getEd25519Pub()));

    const std::vector<std::function<void(RoutedMessage&)>> forgeries = {
        [](RoutedMessage& r) { r.group ^= 0x01; },
        [](RoutedMessage& r) { r.subtype = RouterWire::SUBTYPE_ROUTE_ERROR; },
        [](RoutedMessage& r) { r.mode = RoutingMode::Unicast; r.sourceRoute.reset(); },
        [](RoutedMessage& r) { r.ackRequested = true; },
        [](RoutedMessage& r) { r.reservedFlagBits = 0x80; },
        [](RoutedMessage& r) { r.ttlInitial += 1; },
        [](RoutedMessage& r) { r.msgId ^= 1; },
        [](RoutedMessage& r) { r.sentAtUnixSeconds += 1; },
        [](RoutedMessage& r) { r.sender[0] ^= 1; },
        [](RoutedMessage& r) { (*r.destination)[0] ^= 1; },
        [](RoutedMessage& r) { r.sourceRoute->hops[2][0] ^= 1; },
        [](RoutedMessage& r) { r.sourceRoute->hops.push_back(peerId(0xA4)); },
        [](RoutedMessage& r) { r.extensions[0].value[0] ^= 1; },
        [](RoutedMessage& r) { r.extensions.erase(r.extensions.begin()); },                  // signed extension removed
        [](RoutedMessage& r) { r.extensions.insert(r.extensions.begin(), { 0x06, { 1 } }); },  // signed extension injected
        [](RoutedMessage& r) { r.payload.back() ^= 1; },
    };
    for (size_t i = 0; i < forgeries.size(); ++i) {
        RoutedMessage forged = m;
        forgeries[i](forged);
        EXPECT_FALSE(RouterWire::verifySignature(forged, sender.getEd25519Pub())) << "forgery " << i;
    }

    // The sender's choice of how a message to every node spreads is signed too: a relay cannot switch it
    RoutedMessage broadcast = makeMessage(sender, RoutingMode::Broadcast, Content::Data);
    broadcast.mode = RoutingMode::Flood;
    EXPECT_FALSE(RouterWire::verifySignature(broadcast, sender.getEd25519Pub()));
}

// Without the signed-extensions length, dropping a signed TLV and prepending its bytes to the payload would keep
// bytesToSign identical
TEST(RouterWireTest, MovingSignedExtensionIntoPayloadBreaksSignature) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::Broadcast, Content::Data);
    m.extensions = { { 0x05, { 1, 2 } } };
    signWith(m, sender);

    RoutedMessage forged = m;
    forged.extensions.clear();
    forged.payload.insert(forged.payload.begin(), { 0x05, 0x00, 0x02, 1, 2 });
    EXPECT_FALSE(RouterWire::verifySignature(forged, sender.getEd25519Pub()));
}

TEST(RouterWireTest, VerifyFailsForWrongKeyOrMissingSignature) {
    const auto sender = LocalIdentity::generate();
    const auto other  = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::Broadcast, Content::Data);
    EXPECT_TRUE(RouterWire::verifySignature(m, sender.getEd25519Pub()));
    EXPECT_FALSE(RouterWire::verifySignature(m, other.getEd25519Pub()));
    EXPECT_FALSE(RouterWire::verifySignature(m, std::vector<uint8_t>(31, 0)));
    m.signature.clear();
    EXPECT_FALSE(RouterWire::verifySignature(m, sender.getEd25519Pub()));
}

TEST(RouterWireTest, SignatureRequiredForEveryNodeModesAndRouterMessages) {
    for (const RoutingMode mode : ALL_MODES) {
        EXPECT_TRUE(RouterWire::requiresSignature(RouterWire::ROUTER_PROTOCOL_GROUP, mode));
        EXPECT_EQ(RouterWire::requiresSignature(0x12, mode), RouterWire::reachesEveryNode(mode));
    }
    EXPECT_TRUE(RouterWire::reachesEveryNode(RoutingMode::Flood));
    EXPECT_TRUE(RouterWire::reachesEveryNode(RoutingMode::Broadcast));
    EXPECT_FALSE(RouterWire::reachesEveryNode(RoutingMode::Routed));
    EXPECT_FALSE(RouterWire::reachesEveryNode(RoutingMode::Unicast));
}

// ── Neighbor-only control messages (docs/router.md 3.3) ────────────────────

namespace {
std::vector<RoutedMessageKey> someKeys(size_t count) {
    std::vector<RoutedMessageKey> keys;
    for (size_t i = 0; i < count; ++i) keys.push_back({ peerId(static_cast<uint8_t>(i)), 0x1000 + i });
    return keys;
}

std::span<const uint8_t> payloadOf(const std::vector<uint8_t>& frame) { return std::span<const uint8_t>(frame).subspan(3); }
}

TEST(RouterWireTest, ControlMessagesRoundTrip) {
    for (const size_t count : { size_t(1), size_t(10), size_t(255) }) {
        const auto keys = someKeys(count);
        const auto frame = RouterWire::encodeIhave(keys);
        ASSERT_EQ(frame.size(), 3 + 1 + count * 40);                                         // 40 B per announcement
        EXPECT_EQ(frame[0], RouterWire::ROUTER_PROTOCOL_GROUP);
        EXPECT_EQ((frame[1] << 8) | frame[2], RouterWire::SUBTYPE_IHAVE);
        std::vector<RoutedMessageKey> decoded;
        ASSERT_TRUE(RouterWire::decodeIhave(payloadOf(frame), decoded));
        EXPECT_EQ(decoded, keys);
    }
    EXPECT_EQ(RouterWire::encodeIhave(someKeys(10)).size(), 404u);                          // docs/router.md 3.5

    for (const size_t count : { size_t(0), size_t(3), size_t(255) }) {
        const auto keys = someKeys(count);
        const auto frame = RouterWire::encodeGraft(keys);
        EXPECT_EQ((frame[1] << 8) | frame[2], RouterWire::SUBTYPE_GRAFT);
        std::vector<RoutedMessageKey> decoded = someKeys(2);                                 // overwritten, not appended
        ASSERT_TRUE(RouterWire::decodeGraft(payloadOf(frame), decoded));
        EXPECT_EQ(decoded, keys);
    }

    const auto prune = RouterWire::encodePrune();
    EXPECT_EQ(prune, (std::vector<uint8_t>{ 0xFE, 0x00, 0x04 }));
    EXPECT_TRUE(RouterWire::decodePrune(payloadOf(prune)));

    const UnknownDeliveryModeReport report{ 0x0A, { peerId(0x77), 0xABCDEF0123456789ULL } };
    const auto reportFrame = RouterWire::encodeUnknownDeliveryMode(report);
    EXPECT_EQ(reportFrame.size(), 3u + 41u);
    EXPECT_EQ((reportFrame[1] << 8) | reportFrame[2], RouterWire::SUBTYPE_UNKNOWN_DELIVERY_MODE);
    UnknownDeliveryModeReport decodedReport;
    ASSERT_TRUE(RouterWire::decodeUnknownDeliveryMode(payloadOf(reportFrame), decodedReport));
    EXPECT_EQ(decodedReport, report);

    // None of them carries a routing header
    for (const uint16_t subtype : { RouterWire::SUBTYPE_NEIGHBORS, RouterWire::SUBTYPE_IHAVE, RouterWire::SUBTYPE_GRAFT, RouterWire::SUBTYPE_PRUNE, RouterWire::SUBTYPE_UNKNOWN_DELIVERY_MODE }) {
        EXPECT_FALSE(RouterWire::carriesRoutingHeader(RouterWire::ROUTER_PROTOCOL_GROUP, subtype));
    }
}

TEST(RouterWireTest, ControlEncodersRefuseWhatDoesNotFit) {
    EXPECT_TRUE(RouterWire::encodeIhave({}).empty());                                       // announces nothing
    EXPECT_TRUE(RouterWire::encodeIhave(someKeys(256)).empty());
    EXPECT_TRUE(RouterWire::encodeGraft(someKeys(256)).empty());
}

TEST(RouterWireTest, ControlDecodersRequireExactLength) {
    std::vector<RoutedMessageKey> keys;
    for (const bool graft : { false, true }) {
        SCOPED_TRACE(graft ? "GRAFT" : "IHAVE");
        auto decode = [graft](std::span<const uint8_t> p, std::vector<RoutedMessageKey>& out) { return graft ? RouterWire::decodeGraft(p, out) : RouterWire::decodeIhave(p, out); };
        const auto frame = graft ? RouterWire::encodeGraft(someKeys(2)) : RouterWire::encodeIhave(someKeys(2));
        const std::vector<uint8_t> payload(frame.begin() + 3, frame.end());
        for (size_t length = 0; length < payload.size(); ++length) {
            EXPECT_FALSE(decode(std::span<const uint8_t>(payload).first(length), keys)) << "length " << length;
        }
        std::vector<uint8_t> longer = payload;
        longer.push_back(0);
        EXPECT_FALSE(decode(longer, keys));
        std::vector<uint8_t> miscounted = payload;
        miscounted[0] = 1;                                                                   // count says 1, two keys follow
        EXPECT_FALSE(decode(miscounted, keys));
    }
    const std::vector<uint8_t> zeroCount{ 0x00 };
    EXPECT_FALSE(RouterWire::decodeIhave(zeroCount, keys));
    EXPECT_TRUE(RouterWire::decodeGraft(zeroCount, keys));

    EXPECT_FALSE(RouterWire::decodePrune(std::vector<uint8_t>{ 0x00 }));

    UnknownDeliveryModeReport report;
    const auto reportFrame = RouterWire::encodeUnknownDeliveryMode({ 4, { peerId(1), 2 } });
    std::vector<uint8_t> reportPayload(reportFrame.begin() + 3, reportFrame.end());
    EXPECT_FALSE(RouterWire::decodeUnknownDeliveryMode(std::span<const uint8_t>(reportPayload).first(40), report));
    reportPayload.push_back(0);
    EXPECT_FALSE(RouterWire::decodeUnknownDeliveryMode(reportPayload, report));
}

TEST(RouterWireTest, EncodedSizeMatchesEncode) {
    const auto sender = LocalIdentity::generate();
    for (const RoutingMode mode : ALL_MODES) {
        for (const Content content : ALL_CONTENTS) {
            if (RouterWire::reachesEveryNode(mode) && content != Content::Data) continue;
            for (const bool withExtensions : { false, true }) {
                RoutedMessage m = makeMessage(sender, mode, content);
                if (withExtensions) m.extensions = { { 0x05, { 1, 2, 3 } }, { RouterWire::EXTENSION_SENT_TO, {} } };
                EXPECT_EQ(RouterWire::encodedSize(m), RouterWire::encode(m).size()) << "mode " << int(mode) << " content " << int(content);
            }
        }
    }
}

// ── Route probe (R-5 d) ─────────────────────────────────────────────────────

TEST(RouterWireTest, RouteProbeAndReportPayloadsRoundTrip) {
    const RecordRoutePayload probe{ 1'800'000'000'123ULL, { { peerId(1), 3 }, { peerId(2), 9 } } };
    RecordRoutePayload decodedProbe;
    ASSERT_TRUE(RouterWire::decodeRecordRoutePayload(RouterWire::encodeRecordRoutePayload(probe), decodedProbe));
    EXPECT_EQ(decodedProbe, probe);
    EXPECT_EQ(RouterWire::encodeRecordRoutePayload(probe).size(), 8u + 1u + 2u * 36u);

    const RouteReportPayload report{ 0xABCD, probe.sentAtUnixMs, 15, probe.hops };
    RouteReportPayload decodedReport;
    ASSERT_TRUE(RouterWire::decodeRouteReportPayload(RouterWire::encodeRouteReportPayload(report), decodedReport));
    EXPECT_EQ(decodedReport, report);

    auto cut = RouterWire::encodeRecordRoutePayload(probe);
    cut.pop_back();
    EXPECT_FALSE(RouterWire::decodeRecordRoutePayload(cut, decodedProbe));
    auto longer = RouterWire::encodeRouteReportPayload(report);
    longer.push_back(0);
    EXPECT_FALSE(RouterWire::decodeRouteReportPayload(longer, decodedReport));
    EXPECT_TRUE(RouterWire::encodeRecordRoutePayload({ 0, std::vector<RouteHop>(256) }).empty());
}

// Relays append hops to a signed probe: the sender's signature covers only the send time
TEST(RouterWireTest, RelaysAppendingHopsKeepProbeSignature) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage probe = makeMessage(sender, RoutingMode::Unicast, Content::Ack);
    probe.subtype = RouterWire::SUBTYPE_RECORD_ROUTE;
    probe.payload = RouterWire::encodeRecordRoutePayload({ 1'800'000'000'000ULL, {} });
    signWith(probe, sender);

    RoutedMessage relayed = roundTrip(probe);
    RecordRoutePayload hops;
    ASSERT_TRUE(RouterWire::decodeRecordRoutePayload(relayed.payload, hops));
    hops.hops.push_back({ peerId(0x11), 4 });
    relayed.payload = RouterWire::encodeRecordRoutePayload(hops);
    EXPECT_TRUE(RouterWire::verifySignature(roundTrip(relayed), sender.getEd25519Pub()));

    RecordRoutePayload backdated = hops;
    backdated.sentAtUnixMs -= 1;                                                             // the signed part
    relayed.payload = RouterWire::encodeRecordRoutePayload(backdated);
    EXPECT_FALSE(RouterWire::verifySignature(relayed, sender.getEd25519Pub()));

    // Any other Router message is signed whole
    RoutedMessage ack = makeMessage(sender, RoutingMode::Unicast, Content::Ack);
    ack.payload.push_back(0);
    EXPECT_FALSE(RouterWire::verifySignature(ack, sender.getEd25519Pub()));
}

TEST(RouterWireTest, MalformedProbeIsRejectedOnReceive) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage probe = makeMessage(sender, RoutingMode::Unicast, Content::Ack);
    probe.subtype = RouterWire::SUBTYPE_RECORD_ROUTE;
    probe.payload = { 1, 2, 3 };                                                             // shorter than the send time
    signWith(probe, sender);
    RoutedMessage out;
    EXPECT_EQ(decodeFrame(RouterWire::encode(probe), out), RoutedMessageStatus::MalformedEncoding);
}
