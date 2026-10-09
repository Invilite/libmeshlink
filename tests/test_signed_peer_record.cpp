#include <gtest/gtest.h>
#include "test_helpers.h"

using namespace invilite::Mesh;
using namespace invilite::Mesh::TestHelpers;
using namespace std::chrono_literals;

namespace {

SignedRecordStatus roundTrip(const SignedPeerRecord& record, SignedPeerRecord& out) {
    return SignedPeerRecordCodec::deserialize(SignedPeerRecordCodec::serialize(record), out);
}

} // namespace

TEST(SignedPeerRecordCodecTest, RoundTripPreservesAllFields) {
    const auto identity = LocalIdentity::generate();
    const auto record   = makeSignedRecord(identity, { ipv4("192.0.2.10", 5000), ipv6("2001:db8::1", 5001) }, std::chrono::system_clock::now());

    SignedPeerRecord decoded;
    ASSERT_EQ(roundTrip(record, decoded), SignedRecordStatus::Success);
    EXPECT_EQ(decoded.peerId, identity.getPeerId());
    EXPECT_EQ(decoded.ed25519Pub, record.ed25519Pub);
    EXPECT_EQ(decoded.x25519Pub, record.x25519Pub);
    EXPECT_EQ(decoded.createdAt, record.createdAt);
    EXPECT_EQ(decoded.addresses, record.addresses);
    EXPECT_EQ(decoded.signature, record.signature);
}

TEST(SignedPeerRecordCodecTest, BuildSelfRecordProducesVerifiableRecord) {
    const auto identity = LocalIdentity::generate();
    const auto record   = identity.buildSelfRecord({ ipv4("192.0.2.10", 5000) });

    SignedPeerRecord decoded;
    EXPECT_EQ(roundTrip(record, decoded), SignedRecordStatus::Success);
    EXPECT_EQ(decoded.peerId, identity.getPeerId());
}

TEST(SignedPeerRecordCodecTest, RejectsTamperedSignature) {
    const auto identity = LocalIdentity::generate();
    auto record = makeSignedRecord(identity, { ipv4("192.0.2.10", 5000) }, std::chrono::system_clock::now());
    record.signature[0] ^= 0x01;

    SignedPeerRecord decoded;
    EXPECT_EQ(roundTrip(record, decoded), SignedRecordStatus::SignatureInvalid);
}

TEST(SignedPeerRecordCodecTest, RejectsAddressSwappedAfterSigning) {
    const auto identity = LocalIdentity::generate();
    auto record = makeSignedRecord(identity, { ipv4("192.0.2.10", 5000) }, std::chrono::system_clock::now());
    record.addresses = { ipv4("198.51.100.66", 5000) };

    SignedPeerRecord decoded;
    EXPECT_EQ(roundTrip(record, decoded), SignedRecordStatus::SignatureInvalid);
}

// Records never expire: a node with a static address may never need to re-sign. The signature only proves who may
// update the record; whether the address still works is decided by connecting.
TEST(SignedPeerRecordCodecTest, AcceptsRecordOfAnyAge) {
    const auto identity = LocalIdentity::generate();
    const auto record   = makeSignedRecord(identity, { ipv4("192.0.2.10", 5000) }, std::chrono::system_clock::now() - 2 * 365 * 24h);

    SignedPeerRecord decoded;
    EXPECT_EQ(roundTrip(record, decoded), SignedRecordStatus::Success);
}

TEST(SignedPeerRecordCodecTest, RejectsRecordFromTheFutureBeyondClockSkew) {
    const auto identity = LocalIdentity::generate();
    const auto record   = makeSignedRecord(identity, { ipv4("192.0.2.10", 5000) }, std::chrono::system_clock::now() + 10min);

    SignedPeerRecord decoded;
    EXPECT_EQ(roundTrip(record, decoded), SignedRecordStatus::TimestampOutOfRange);
}

TEST(SignedPeerRecordCodecTest, AcceptsRecordWithinClockSkew) {
    const auto identity = LocalIdentity::generate();
    const auto record   = makeSignedRecord(identity, { ipv4("192.0.2.10", 5000) }, std::chrono::system_clock::now() + 2min);

    SignedPeerRecord decoded;
    EXPECT_EQ(roundTrip(record, decoded), SignedRecordStatus::Success);
}

TEST(SignedPeerRecordCodecTest, RejectsTruncatedData) {
    const auto identity = LocalIdentity::generate();
    auto bytes = SignedPeerRecordCodec::serialize(makeSignedRecord(identity, { ipv4("192.0.2.10", 5000) }, std::chrono::system_clock::now()));

    for (size_t cut = 1; cut < bytes.size(); cut += 7) {
        const std::vector<uint8_t> truncated(bytes.begin(), bytes.end() - static_cast<std::ptrdiff_t>(cut));
        SignedPeerRecord decoded;
        EXPECT_NE(SignedPeerRecordCodec::deserialize(truncated, decoded), SignedRecordStatus::Success) << "cut=" << cut;
    }
}

TEST(SignedPeerRecordCodecTest, RejectsEmptyInput) {
    SignedPeerRecord decoded;
    EXPECT_EQ(SignedPeerRecordCodec::deserialize({}, decoded), SignedRecordStatus::MalformedEncoding);
}

TEST(SignedPeerRecordCodecTest, SerializeForSigningRejectsInvalidAddressText) {
    const auto identity = LocalIdentity::generate();
    const auto bytes = SignedPeerRecordCodec::serializeForSigning(identity.getEd25519Pub(), identity.getX25519Pub(), std::chrono::system_clock::now(), { ipv4("not-an-ip", 5000) });
    EXPECT_TRUE(bytes.empty());
}
