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
    records[1] = makeSignedRecord(LocalIdentity::generate(), { ipv4("192.0.2.10", 5000) }, std::chrono::system_clock::now() - 48h);   // stale

    std::vector<SignedPeerRecord> decoded;
    ASSERT_EQ(PexAnnounceCodec::deserialize(PexAnnounceCodec::serialize(records), decoded), PexAnnounceStatus::Success);
    ASSERT_EQ(decoded.size(), 2u);
    EXPECT_EQ(decoded[0].peerId, records[0].peerId);
    EXPECT_EQ(decoded[1].peerId, records[2].peerId);
}
