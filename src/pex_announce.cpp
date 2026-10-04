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
    out.reserve(COUNT_SIZE + maxCount * 300);                                       // ~max record size, generous pre-alloc
    out.push_back(0);                                                               // count placeholder — patched at the end

    uint8_t actualCount = 0;
    for (size_t i = 0; i < maxCount; ++i) {
        const std::vector<uint8_t> bytes = SignedPeerRecordCodec::serialize(records[i]);
        if (bytes.empty())              continue;                                   // skip records that failed to serialize
        if (bytes.size() > UINT16_MAX)  continue;                                   // defensive — length must fit 2B

        writeBE16(out, static_cast<uint16_t>(bytes.size()));
        out.insert(out.end(), bytes.begin(), bytes.end());
        ++actualCount;
    }

    out[0] = actualCount;                                                           // patch actual count
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
        // else: framing is fine, this individual record failed verification — skip silently.
        // Caller comparing outRecords.size() vs expected can detect skipped records if needed.
    }

    // No trailing bytes allowed — tightens the format and helps catch subtle bugs.
    if (offset != data.size()) return PexAnnounceStatus::MalformedEncoding;

    return PexAnnounceStatus::Success;
}

} // namespace invilite::Mesh::PexAnnounceCodec