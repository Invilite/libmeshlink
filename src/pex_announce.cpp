#include "meshlink/pex_announce.h"

#include <algorithm>
#include <climits>

namespace invilite::Mesh::PexAnnounceCodec {

namespace {
    constexpr size_t COUNT_SIZE      = 1;
    constexpr size_t RECORD_LEN_SIZE = 2;

    void writeBE16(std::vector<uint8_t>& out, uint16_t v) {
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(v & 0xFF));
    }

    uint16_t readBE16(std::span<const uint8_t> data, size_t offset) {
        return (static_cast<uint16_t>(data[offset]) << 8) | static_cast<uint16_t>(data[offset + 1]);
    }
}

std::vector<uint8_t> serialize(const std::vector<SignedPeerRecord>& records) {
    const size_t maxCount = std::min<size_t>(records.size(), MAX_RECORDS_PER_BATCH);

    std::vector<uint8_t> out;
    out.reserve(COUNT_SIZE + maxCount * 300);                                       // rough upper bound of one record
    out.push_back(0);                                                               // count placeholder, patched below

    uint8_t actualCount = 0;
    for (size_t i = 0; i < maxCount; ++i) {
        const std::vector<uint8_t> bytes = SignedPeerRecordCodec::serialize(records[i]);
        if (bytes.empty())              continue;
        if (bytes.size() > UINT16_MAX)  continue;                                   // length must fit 2 bytes

        writeBE16(out, static_cast<uint16_t>(bytes.size()));
        out.insert(out.end(), bytes.begin(), bytes.end());
        ++actualCount;
    }

    out[0] = actualCount;
    return out;
}

PexAnnounceStatus deserialize(std::span<const uint8_t> data, std::vector<SignedPeerRecord>& outRecords) {
    outRecords.clear();

    if (data.size() < COUNT_SIZE) return PexAnnounceStatus::MalformedEncoding;

    const uint8_t count = data[0];
    if (count > MAX_RECORDS_PER_BATCH) return PexAnnounceStatus::MalformedEncoding;

    size_t offset = COUNT_SIZE;
    outRecords.reserve(count);

    for (uint8_t i = 0; i < count; ++i) {
        if (offset + RECORD_LEN_SIZE > data.size()) return PexAnnounceStatus::MalformedEncoding;

        const uint16_t recordLen = readBE16(data, offset);
        offset += RECORD_LEN_SIZE;

        if (offset + recordLen > data.size()) return PexAnnounceStatus::MalformedEncoding;

        const std::span<const uint8_t> recordBytes{ data.data() + offset, recordLen };
        offset += recordLen;

        SignedPeerRecord record;
        if (SignedPeerRecordCodec::deserialize(recordBytes, record) == SignedRecordStatus::Success) {
            outRecords.push_back(std::move(record));
        }
        // A record that fails verification is skipped; the framing is still valid.
    }

    if (offset != data.size()) return PexAnnounceStatus::MalformedEncoding;

    return PexAnnounceStatus::Success;
}

} // namespace invilite::Mesh::PexAnnounceCodec

namespace invilite::Mesh::PexRequestCodec {

namespace {
    constexpr size_t COUNT_SIZE   = 1;
    constexpr size_t PEER_ID_SIZE = 32;
}

std::vector<uint8_t> serialize(const std::vector<PeerId>& wanted) {
    if (wanted.empty() || wanted.size() > PexAnnounceCodec::MAX_RECORDS_PER_BATCH) return {};

    std::vector<uint8_t> out;
    out.reserve(COUNT_SIZE + wanted.size() * PEER_ID_SIZE);
    out.push_back(static_cast<uint8_t>(wanted.size()));
    for (const PeerId& id : wanted) out.insert(out.end(), id.begin(), id.end());
    return out;
}

PexAnnounceStatus deserialize(std::span<const uint8_t> data, std::vector<PeerId>& outWanted) {
    outWanted.clear();
    if (data.size() < COUNT_SIZE) return PexAnnounceStatus::MalformedEncoding;

    const uint8_t count = data[0];
    if (count == 0 || count > PexAnnounceCodec::MAX_RECORDS_PER_BATCH) return PexAnnounceStatus::MalformedEncoding;
    if (data.size() != COUNT_SIZE + count * PEER_ID_SIZE)               return PexAnnounceStatus::MalformedEncoding;

    outWanted.resize(count);
    for (uint8_t i = 0; i < count; ++i) std::copy_n(data.begin() + COUNT_SIZE + i * PEER_ID_SIZE, PEER_ID_SIZE, outWanted[i].begin());
    return PexAnnounceStatus::Success;
}

} // namespace invilite::Mesh::PexRequestCodec
