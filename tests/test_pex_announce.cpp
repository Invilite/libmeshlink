#include <gtest/gtest.h>
#include "meshlink/pex_announce.h"
#include "test_helpers.h"

using namespace invilite::Mesh;
using namespace invilite::Mesh::TestHelpers;
using namespace std::chrono_literals;

namespace {

std::vector<SignedPeerRecord> makeFreshRecords(size_t count) {
    std::vector<SignedPeerRecord> records;
    for (size_t i = 0; i < count; ++i) {
        records.push_back(makeSignedRecord(LocalIdentity::generate(), { ipv4("192.0.2.10", static_cast<uint16_t>(5000 + i)) }, std::chrono::system_clock::now()));
    }
    return records;
}

} // namespace

TEST(PexAnnounceCodecTest, RoundTripPreservesRecordsAndOrder) {
    const auto records = makeFreshRecords(3);

    std::vector<SignedPeerRecord> decoded;
    ASSERT_EQ(PexAnnounceCodec::deserialize(PexAnnounceCodec::serialize(records), decoded), PexAnnounceStatus::Success);
    ASSERT_EQ(decoded.size(), records.size());
    for (size_t i = 0; i < records.size(); ++i) {
        EXPECT_EQ(decoded[i].peerId, records[i].peerId);
        EXPECT_EQ(decoded[i].addresses, records[i].addresses);
    }
}

TEST(PexAnnounceCodecTest, EmptyBatchRoundTrips) {
    std::vector<SignedPeerRecord> decoded;
    EXPECT_EQ(PexAnnounceCodec::deserialize(PexAnnounceCodec::serialize({}), decoded), PexAnnounceStatus::Success);
    EXPECT_TRUE(decoded.empty());
}

TEST(PexAnnounceCodecTest, SerializeTruncatesToBatchCap) {
    const auto records = makeFreshRecords(PexAnnounceCodec::MAX_RECORDS_PER_BATCH + 3);

    const auto payload = PexAnnounceCodec::serialize(records);
    ASSERT_FALSE(payload.empty());
    EXPECT_EQ(payload[0], PexAnnounceCodec::MAX_RECORDS_PER_BATCH);

    std::vector<SignedPeerRecord> decoded;
    ASSERT_EQ(PexAnnounceCodec::deserialize(payload, decoded), PexAnnounceStatus::Success);
    EXPECT_EQ(decoded.size(), PexAnnounceCodec::MAX_RECORDS_PER_BATCH);
}

TEST(PexAnnounceCodecTest, RejectsCountAboveCap) {
    auto payload = PexAnnounceCodec::serialize({});
    payload[0] = PexAnnounceCodec::MAX_RECORDS_PER_BATCH + 1;

    std::vector<SignedPeerRecord> decoded;
    EXPECT_EQ(PexAnnounceCodec::deserialize(payload, decoded), PexAnnounceStatus::MalformedEncoding);
}

TEST(PexAnnounceCodecTest, RejectsTrailingBytes) {
    auto payload = PexAnnounceCodec::serialize(makeFreshRecords(1));
    payload.push_back(0x00);

    std::vector<SignedPeerRecord> decoded;
    EXPECT_EQ(PexAnnounceCodec::deserialize(payload, decoded), PexAnnounceStatus::MalformedEncoding);
}

TEST(PexAnnounceCodecTest, RejectsTruncatedBatch) {
    const auto payload = PexAnnounceCodec::serialize(makeFreshRecords(2));

    for (size_t cut = 1; cut < payload.size(); cut += 11) {
        const std::vector<uint8_t> truncated(payload.begin(), payload.end() - static_cast<std::ptrdiff_t>(cut));
        std::vector<SignedPeerRecord> decoded;
        EXPECT_EQ(PexAnnounceCodec::deserialize(truncated, decoded), PexAnnounceStatus::MalformedEncoding) << "cut=" << cut;
    }
}

TEST(PexAnnounceCodecTest, SkipsInvalidRecordButKeepsTheRest) {
    auto records = makeFreshRecords(3);
    records[1].signature[0] ^= 0x01;                                                         // tampered

    std::vector<SignedPeerRecord> decoded;
    ASSERT_EQ(PexAnnounceCodec::deserialize(PexAnnounceCodec::serialize(records), decoded), PexAnnounceStatus::Success);
    ASSERT_EQ(decoded.size(), 2u);
    EXPECT_EQ(decoded[0].peerId, records[0].peerId);
    EXPECT_EQ(decoded[1].peerId, records[2].peerId);
}

// ── PEX_REQUEST ─────────────────────────────────────────────────────────────

namespace {
PeerId filledPeerId(uint8_t fill) { PeerId id; id.fill(fill); return id; }
}

TEST(PexRequestCodecTest, RoundTripPreservesIdsAndOrder) {
    const std::vector<PeerId> wanted{ filledPeerId(3), filledPeerId(1), filledPeerId(2) };
    std::vector<PeerId> decoded;
    ASSERT_EQ(PexRequestCodec::deserialize(PexRequestCodec::serialize(wanted), decoded), PexAnnounceStatus::Success);
    EXPECT_EQ(decoded, wanted);
}

TEST(PexRequestCodecTest, SerializeRefusesEmptyAndOversizedRequests) {
    EXPECT_TRUE(PexRequestCodec::serialize({}).empty());
    EXPECT_FALSE(PexRequestCodec::serialize(std::vector<PeerId>(PexAnnounceCodec::MAX_RECORDS_PER_BATCH)).empty());
    EXPECT_TRUE(PexRequestCodec::serialize(std::vector<PeerId>(PexAnnounceCodec::MAX_RECORDS_PER_BATCH + 1)).empty());
}

TEST(PexRequestCodecTest, RejectsMalformedPayloads) {
    std::vector<PeerId> decoded;
    const auto valid = PexRequestCodec::serialize({ filledPeerId(1), filledPeerId(2) });

    EXPECT_EQ(PexRequestCodec::deserialize({}, decoded), PexAnnounceStatus::MalformedEncoding);
    EXPECT_EQ(PexRequestCodec::deserialize(std::vector<uint8_t>{ 0 }, decoded), PexAnnounceStatus::MalformedEncoding);           // count 0
    std::vector<uint8_t> overCap(1 + 33 * 32, 0);
    overCap[0] = 33;
    EXPECT_EQ(PexRequestCodec::deserialize(overCap, decoded), PexAnnounceStatus::MalformedEncoding);
    EXPECT_EQ(PexRequestCodec::deserialize(std::span(valid).first(valid.size() - 1), decoded), PexAnnounceStatus::MalformedEncoding);
    auto trailing = valid;
    trailing.push_back(0);
    EXPECT_EQ(PexRequestCodec::deserialize(trailing, decoded), PexAnnounceStatus::MalformedEncoding);
}
