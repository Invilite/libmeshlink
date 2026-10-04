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

// A valid message of the given mode/kind with every optional part the mode requires; signed when required
RoutedMessage makeMessage(const LocalIdentity& sender, RoutingMode mode, RoutedMessageKind kind) {
    RoutedMessage m;
    m.group             = 0x12;
    m.subtype           = 0xABCD;
    m.mode              = mode;
    m.kind              = kind;
    m.ttlInitial        = 16;
    m.ttlRemaining      = 13;
    m.msgId             = 0x0102030405060708ULL;
    m.sentAtUnixSeconds = NOW_SECONDS;
    m.sender            = sender.getPeerId();
    if (mode != RoutingMode::Broadcast)     m.destination = peerId(0xDD);
    if (mode == RoutingMode::SourceRouted)  m.sourceRoute = SourceRoute{ 1, { peerId(0xA1), peerId(0xA2), peerId(0xA3) } };
    if (kind == RoutedMessageKind::Ack)              m.payload = RouterWire::encodeAckPayload({ 0x1111, { peerId(0xB1), peerId(0xB2) } });
    else if (kind == RoutedMessageKind::RouteError)  m.payload = RouterWire::encodeRouteErrorPayload({ 0x2222, peerId(0xC1), RouteErrorReason::NextHopNotNeighbor });
    else                                             m.payload = { 'h', 'e', 'l', 'l', 'o' };
    if (RouterWire::requiresSignature(mode, kind)) signWith(m, sender);
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

const RoutingMode ALL_MODES[] = { RoutingMode::Broadcast, RoutingMode::Unicast, RoutingMode::SourceRouted, RoutingMode::Flood };
const RoutedMessageKind ALL_KINDS[] = { RoutedMessageKind::Data, RoutedMessageKind::Ack, RoutedMessageKind::RouteError };

// Offsets inside an encoded frame (Group | Subtype precede the routing header)
constexpr size_t VERSION_MODE_OFFSET = 3;
constexpr size_t FLAGS_OFFSET        = 4;
constexpr size_t TTL_REMAINING_OFFSET = 5;
constexpr size_t TTL_INITIAL_OFFSET  = 6;
constexpr size_t SENT_AT_OFFSET      = 15;
constexpr size_t AFTER_FIXED_OFFSET  = 3 + RouterWire::FIXED_HEADER_SIZE;

} // namespace

// ── Round trip ──────────────────────────────────────────────────────────────

TEST(RouterWireTest, RoundTripEveryModeKindAndFlagCombination) {
    const auto sender = LocalIdentity::generate();
    for (const RoutingMode mode : ALL_MODES) {
        for (const RoutedMessageKind kind : ALL_KINDS) {
            if (mode == RoutingMode::Broadcast && kind != RoutedMessageKind::Data) continue;
            for (const bool recordRoute : { false, true }) {
                for (const bool ackRequested : { false, true }) {
                    for (const bool withExtensions : { false, true }) {
                        SCOPED_TRACE(testing::Message() << "mode=" << int(mode) << " kind=" << int(kind) << " record=" << recordRoute << " ack=" << ackRequested << " ext=" << withExtensions);
                        RoutedMessage m = makeMessage(sender, mode, kind);
                        m.ackRequested = ackRequested;
                        if (recordRoute)    m.recordedRoute = std::vector<PeerId>{ peerId(0xE1), peerId(0xE2) };
                        if (withExtensions) m.extensions = { { 0x05, { 1, 2, 3 } }, { RouterWire::EXTENSION_SENT_TO, { 0xFF, 0x00 } } };
                        if (RouterWire::requiresSignature(mode, kind)) signWith(m, sender);

                        const RoutedMessage decoded = roundTrip(m);
                        EXPECT_EQ(decoded, m);
                        if (RouterWire::requiresSignature(mode, kind)) { EXPECT_TRUE(RouterWire::verifySignature(decoded, sender.getEd25519Pub())); }
                    }
                }
            }
        }
    }
}

TEST(RouterWireTest, RoundTripEmptyPayloadAndEmptyLists) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::SourceRouted, RoutedMessageKind::Data);
    m.payload.clear();
    m.sourceRoute = SourceRoute{ 0, {} };
    m.recordedRoute = std::vector<PeerId>{};
    EXPECT_EQ(roundTrip(m), m);
}

TEST(RouterWireTest, RoundTripMaximalListsAndExtensionLengths) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::SourceRouted, RoutedMessageKind::Data);
    m.sourceRoute = SourceRoute{ 255, std::vector<PeerId>(255, peerId(0x01)) };
    m.recordedRoute = std::vector<PeerId>(255, peerId(0x02));
    m.extensions = { { 0x07, std::vector<uint8_t>(0xFFFF - 3, 0x5A) } };                     // fills the 2-byte block length exactly
    EXPECT_EQ(roundTrip(m), m);
}

// Overhead table in docs/router.md 3.5 (Network header + routing header, without the payload)
TEST(RouterWireTest, EncodedOverheadMatchesDesign) {
    const auto sender = LocalIdentity::generate();
    auto overhead = [](RoutedMessage m) { m.payload.clear(); if (!m.signature.empty()) m.signature.assign(64, 0); return RouterWire::encode(m).size(); };

    EXPECT_EQ(overhead(makeMessage(sender, RoutingMode::Broadcast, RoutedMessageKind::Data)), 115u);
    EXPECT_EQ(overhead(makeMessage(sender, RoutingMode::Unicast, RoutedMessageKind::Data)), 83u);

    RoutedMessage recorded = makeMessage(sender, RoutingMode::Unicast, RoutedMessageKind::Data);
    recorded.recordedRoute = std::vector<PeerId>(5, peerId(0x01));
    EXPECT_EQ(overhead(recorded), 244u);

    RoutedMessage sourceRouted = makeMessage(sender, RoutingMode::SourceRouted, RoutedMessageKind::Data);
    sourceRouted.sourceRoute = SourceRoute{ 0, std::vector<PeerId>(5, peerId(0x01)) };
    EXPECT_EQ(overhead(sourceRouted), 245u);
}

TEST(RouterWireTest, UnknownExtensionsAndReservedFlagBitsSurviveRoundTrip) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::Broadcast, RoutedMessageKind::Data);
    m.reservedFlagBits = 0xA0;                                                              // a future sender sets reserved bits
    m.extensions = { { 0x3E, { 9 } }, { 0x7E, { 8 } } };                                    // unknown signed + unknown per-hop, both non-critical
    signWith(m, sender);

    const RoutedMessage decoded = roundTrip(m);
    EXPECT_EQ(decoded, m);
    EXPECT_TRUE(RouterWire::verifySignature(decoded, sender.getEd25519Pub()));             // a relay re-encoding it does not break the signature
    EXPECT_TRUE(RouterWire::verifySignature(roundTrip(decoded), sender.getEd25519Pub()));
}

TEST(RouterWireTest, KindPayloadsRoundTrip) {
    const AckPayload ack{ 0xDEADBEEFCAFEF00DULL, { peerId(1), peerId(2), peerId(3) } };
    AckPayload decodedAck;
    ASSERT_TRUE(RouterWire::decodeAckPayload(RouterWire::encodeAckPayload(ack), decodedAck));
    EXPECT_EQ(decodedAck, ack);

    const RouteErrorPayload error{ 42, peerId(7), static_cast<RouteErrorReason>(0x77) };   // unknown reason is kept
    RouteErrorPayload decodedError;
    ASSERT_TRUE(RouterWire::decodeRouteErrorPayload(RouterWire::encodeRouteErrorPayload(error), decodedError));
    EXPECT_EQ(decodedError, error);
}

TEST(RouterWireTest, KindPayloadDecodersRequireExactLength) {
    auto ack = RouterWire::encodeAckPayload({ 1, { peerId(1) } });
    AckPayload decodedAck;
    ack.push_back(0);
    EXPECT_FALSE(RouterWire::decodeAckPayload(ack, decodedAck));
    ack.resize(ack.size() - 2);
    EXPECT_FALSE(RouterWire::decodeAckPayload(ack, decodedAck));

    auto error = RouterWire::encodeRouteErrorPayload({ 1, peerId(1), RouteErrorReason::NextHopSendRefused });
    RouteErrorPayload decodedError;
    error.push_back(0);
    EXPECT_FALSE(RouterWire::decodeRouteErrorPayload(error, decodedError));
    error.resize(error.size() - 2);
    EXPECT_FALSE(RouterWire::decodeRouteErrorPayload(error, decodedError));

    EXPECT_TRUE(RouterWire::encodeAckPayload({ 1, std::vector<PeerId>(256) }).empty());
}

// ── Encode refuses inconsistent messages ────────────────────────────────────

TEST(RouterWireTest, EncodeRefusesInconsistentMessages) {
    const auto sender = LocalIdentity::generate();
    const RoutedMessage unicast   = makeMessage(sender, RoutingMode::Unicast, RoutedMessageKind::Data);
    const RoutedMessage broadcast = makeMessage(sender, RoutingMode::Broadcast, RoutedMessageKind::Data);
    const RoutedMessage routed    = makeMessage(sender, RoutingMode::SourceRouted, RoutedMessageKind::Data);
    ASSERT_FALSE(RouterWire::encode(unicast).empty());
    ASSERT_FALSE(RouterWire::encode(broadcast).empty());
    ASSERT_FALSE(RouterWire::encode(routed).empty());

    auto refused = [](RoutedMessage m, auto change) { change(m); return RouterWire::encode(m).empty(); };
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.group = 0xFE; }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.group = 0xFF; }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.mode = static_cast<RoutingMode>(4); }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.kind = static_cast<RoutedMessageKind>(3); }));
    EXPECT_TRUE(refused(broadcast, [](RoutedMessage& m) { m.kind = RoutedMessageKind::Ack; }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.reservedFlagBits = 0x10; }));    // not a reserved bit (HAS_EXTENSIONS)
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.ttlInitial = 0; m.ttlRemaining = 0; }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.ttlRemaining = m.ttlInitial + 1; }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.destination.reset(); }));
    EXPECT_TRUE(refused(broadcast, [](RoutedMessage& m) { m.destination = peerId(1); }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.sourceRoute = SourceRoute{}; }));
    EXPECT_TRUE(refused(routed,    [](RoutedMessage& m) { m.sourceRoute.reset(); }));
    EXPECT_TRUE(refused(routed,    [](RoutedMessage& m) { m.sourceRoute->nextHopIndex = 4; }));
    EXPECT_TRUE(refused(routed,    [](RoutedMessage& m) { m.sourceRoute->hops.resize(256); m.sourceRoute->nextHopIndex = 0; }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.recordedRoute = std::vector<PeerId>(256); }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.extensions = { { 1, std::vector<uint8_t>(0x10000) } }; }));
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.extensions = { { 1, std::vector<uint8_t>(0x8000) }, { 2, std::vector<uint8_t>(0x8000) } }; }));
    EXPECT_TRUE(refused(broadcast, [](RoutedMessage& m) { m.signature.clear(); }));             // signature required
    EXPECT_TRUE(refused(unicast,   [](RoutedMessage& m) { m.signature.assign(64, 0); }));       // UNICAST DATA carries none
}

// ── Receive validation (docs/router.md 3.6) — each rule rejects ─────────────

TEST(RouterWireTest, RejectsNonRoutedGroups) {
    const auto frame = RouterWire::encode(makeMessage(LocalIdentity::generate(), RoutingMode::Unicast, RoutedMessageKind::Data));
    RoutedMessage out;
    for (const uint8_t group : { uint8_t(0xFE), uint8_t(0xFF) }) {
        EXPECT_EQ(RouterWire::decode(group, 0, std::span<const uint8_t>(frame).subspan(3), NOW, out), RoutedMessageStatus::NotRoutedGroup);
    }
    EXPECT_EQ(RouterWire::decode(0xFD, 0, std::span<const uint8_t>(frame).subspan(3), NOW, out), RoutedMessageStatus::Success);
}

TEST(RouterWireTest, RejectsHeaderFieldViolations) {
    const auto sender = LocalIdentity::generate();
    const auto unicast   = RouterWire::encode(makeMessage(sender, RoutingMode::Unicast, RoutedMessageKind::Data));
    const auto broadcast = RouterWire::encode(makeMessage(sender, RoutingMode::Broadcast, RoutedMessageKind::Data));

    auto statusAfter = [](std::vector<uint8_t> frame, auto change) { change(frame); RoutedMessage out; return decodeFrame(frame, out); };

    EXPECT_EQ(statusAfter(unicast, [](auto& f) { f[VERSION_MODE_OFFSET] = 0x21; }), RoutedMessageStatus::UnsupportedVersion);
    EXPECT_EQ(statusAfter(unicast, [](auto& f) { f[VERSION_MODE_OFFSET] = 0x01; }), RoutedMessageStatus::UnsupportedVersion);
    for (uint8_t mode = 4; mode <= 0xF; ++mode) {
        EXPECT_EQ(statusAfter(unicast, [mode](auto& f) { f[VERSION_MODE_OFFSET] = 0x10 | mode; }), RoutedMessageStatus::ReservedMode);
    }
    EXPECT_EQ(statusAfter(unicast, [](auto& f) { f[FLAGS_OFFSET] |= 0x03; }), RoutedMessageStatus::ReservedKind);
    EXPECT_EQ(statusAfter(broadcast, [](auto& f) { f[FLAGS_OFFSET] |= 0x01; }), RoutedMessageStatus::KindNotAllowedInMode);
    EXPECT_EQ(statusAfter(broadcast, [](auto& f) { f[FLAGS_OFFSET] |= 0x02; }), RoutedMessageStatus::KindNotAllowedInMode);
    EXPECT_EQ(statusAfter(unicast, [](auto& f) { f[TTL_INITIAL_OFFSET] = 0; f[TTL_REMAINING_OFFSET] = 0; }), RoutedMessageStatus::InvalidTtl);
    EXPECT_EQ(statusAfter(unicast, [](auto& f) { f[TTL_REMAINING_OFFSET] = f[TTL_INITIAL_OFFSET] + 1; }), RoutedMessageStatus::InvalidTtl);
    EXPECT_EQ(statusAfter(unicast, [](auto& f) { f[TTL_REMAINING_OFFSET] = 0; }), RoutedMessageStatus::Success);   // TTL used up: deliver, do not forward
}

TEST(RouterWireTest, RejectsTimestampOutsideWindow) {
    const auto frame = RouterWire::encode(makeMessage(LocalIdentity::generate(), RoutingMode::Unicast, RoutedMessageKind::Data));
    RoutedMessage out;
    EXPECT_EQ(decodeFrame(frame, out, NOW + 5min), RoutedMessageStatus::Success);
    EXPECT_EQ(decodeFrame(frame, out, NOW - 5min), RoutedMessageStatus::Success);
    EXPECT_EQ(decodeFrame(frame, out, NOW + 5min + 1s), RoutedMessageStatus::TimestampOutOfWindow);   // message too old
    EXPECT_EQ(decodeFrame(frame, out, NOW - 5min - 1s), RoutedMessageStatus::TimestampOutOfWindow);   // message from the future
}

TEST(RouterWireTest, RejectsSourceRouteIndexPastRoute) {
    auto frame = RouterWire::encode(makeMessage(LocalIdentity::generate(), RoutingMode::SourceRouted, RoutedMessageKind::Data));
    const size_t indexOffset = AFTER_FIXED_OFFSET + 32 + 1;                                  // after destination and hop count (3)
    RoutedMessage out;
    frame[indexOffset] = 3;
    EXPECT_EQ(decodeFrame(frame, out), RoutedMessageStatus::Success);                        // route used up, destination is next
    frame[indexOffset] = 4;
    EXPECT_EQ(decodeFrame(frame, out), RoutedMessageStatus::SourceRouteIndexOutOfRange);
}

TEST(RouterWireTest, RejectsUnknownCriticalExtensionButKeepsUnknownNonCritical) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::Unicast, RoutedMessageKind::Data);
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
    RoutedMessage m = makeMessage(sender, RoutingMode::SourceRouted, RoutedMessageKind::Ack);
    m.recordedRoute = std::vector<PeerId>{ peerId(0xE1) };
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
    RoutedMessage routed = makeMessage(sender, RoutingMode::SourceRouted, RoutedMessageKind::Data);
    routed.payload.clear();
    auto frame = RouterWire::encode(routed);
    frame[AFTER_FIXED_OFFSET + 32] = 4;
    EXPECT_EQ(decodeFrame(frame, out), RoutedMessageStatus::MalformedEncoding);

    // Recorded route claims more hops than the frame holds
    RoutedMessage recorded = makeMessage(sender, RoutingMode::Unicast, RoutedMessageKind::Data);
    recorded.recordedRoute = std::vector<PeerId>{ peerId(1) };
    recorded.payload.clear();
    frame = RouterWire::encode(recorded);
    frame[AFTER_FIXED_OFFSET + 32] = 2;
    EXPECT_EQ(decodeFrame(frame, out), RoutedMessageStatus::MalformedEncoding);

    // Extension block longer than the rest of the frame
    RoutedMessage extended = makeMessage(sender, RoutingMode::Unicast, RoutedMessageKind::Data);
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
    RoutedMessage plain = makeMessage(sender, RoutingMode::Unicast, RoutedMessageKind::Data);
    plain.payload.clear();
    frame = RouterWire::encode(plain);
    frame[FLAGS_OFFSET] |= 0x10;
    EXPECT_EQ(decodeFrame(frame, out), RoutedMessageStatus::MalformedEncoding);
}

TEST(RouterWireTest, RejectsMalformedKindPayloads) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage out;
    for (const RoutedMessageKind kind : { RoutedMessageKind::Ack, RoutedMessageKind::RouteError }) {
        RoutedMessage m = makeMessage(sender, RoutingMode::Unicast, kind);
        m.payload.push_back(0);                                                              // trailing byte
        signWith(m, sender);
        EXPECT_EQ(decodeFrame(RouterWire::encode(m), out), RoutedMessageStatus::MalformedEncoding);
    }
}

// ── Signature: [M] fields may change, [S] fields may not ────────────────────

TEST(RouterWireTest, RelayMutableFieldsDoNotBreakSignature) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::SourceRouted, RoutedMessageKind::Ack);
    m.recordedRoute = std::vector<PeerId>{ peerId(0xE1) };
    m.extensions = { { 0x05, { 1 } }, { RouterWire::EXTENSION_SENT_TO, { 0xAA } } };
    signWith(m, sender);

    const std::vector<std::function<void(RoutedMessage&)>> relayChanges = {
        [](RoutedMessage& r) { r.ttlRemaining -= 1; },
        [](RoutedMessage& r) { r.sourceRoute->nextHopIndex += 1; },
        [](RoutedMessage& r) { r.recordedRoute->push_back(peerId(0xE2)); },
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
    RoutedMessage broadcast = makeMessage(sender, RoutingMode::Broadcast, RoutedMessageKind::Data);
    broadcast.extensions.push_back({ RouterWire::EXTENSION_SENT_TO, { 0x01 } });
    EXPECT_TRUE(RouterWire::verifySignature(roundTrip(broadcast), sender.getEd25519Pub()));
}

TEST(RouterWireTest, SignedFieldChangesBreakSignature) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::SourceRouted, RoutedMessageKind::Ack);
    m.extensions = { { 0x05, { 1 } }, { RouterWire::EXTENSION_SENT_TO, { 0xAA } } };
    signWith(m, sender);
    ASSERT_TRUE(RouterWire::verifySignature(m, sender.getEd25519Pub()));

    const std::vector<std::function<void(RoutedMessage&)>> forgeries = {
        [](RoutedMessage& r) { r.group ^= 0x01; },
        [](RoutedMessage& r) { r.subtype ^= 0x0001; },
        [](RoutedMessage& r) { r.mode = RoutingMode::Unicast; r.sourceRoute.reset(); },
        [](RoutedMessage& r) { r.kind = RoutedMessageKind::RouteError; },
        [](RoutedMessage& r) { r.ackRequested = true; },
        [](RoutedMessage& r) { r.recordedRoute = std::vector<PeerId>{}; },                  // RECORD_ROUTE flag is signed
        [](RoutedMessage& r) { r.reservedFlagBits = 0x20; },
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
}

// Without the signed-extensions length, dropping a signed TLV and prepending its bytes to the payload would keep
// bytesToSign identical
TEST(RouterWireTest, MovingSignedExtensionIntoPayloadBreaksSignature) {
    const auto sender = LocalIdentity::generate();
    RoutedMessage m = makeMessage(sender, RoutingMode::Broadcast, RoutedMessageKind::Data);
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
    RoutedMessage m = makeMessage(sender, RoutingMode::Broadcast, RoutedMessageKind::Data);
    EXPECT_TRUE(RouterWire::verifySignature(m, sender.getEd25519Pub()));
    EXPECT_FALSE(RouterWire::verifySignature(m, other.getEd25519Pub()));
    EXPECT_FALSE(RouterWire::verifySignature(m, std::vector<uint8_t>(31, 0)));
    m.signature.clear();
    EXPECT_FALSE(RouterWire::verifySignature(m, sender.getEd25519Pub()));
}

TEST(RouterWireTest, SignatureRequiredExactlyForBroadcastAckAndRouteError) {
    for (const RoutingMode mode : ALL_MODES) {
        EXPECT_TRUE(RouterWire::requiresSignature(mode, RoutedMessageKind::Ack));
        EXPECT_TRUE(RouterWire::requiresSignature(mode, RoutedMessageKind::RouteError));
        EXPECT_EQ(RouterWire::requiresSignature(mode, RoutedMessageKind::Data), mode == RoutingMode::Broadcast);
    }
}
