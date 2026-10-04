#pragma once

#ifndef MESH_PEX_ANNOUNCE_H
#define MESH_PEX_ANNOUNCE_H

#include "meshlink/signed_peer_record.h"

#include <cstdint>
#include <span>
#include <vector>

namespace invilite::Mesh {

    // PEX_ANNOUNCE payload format (group 0xFF / subtype 0x0020):
    //
    //   count        (1B, max MAX_RECORDS_PER_BATCH)
    //   for each record:
    //       recordLen (2B BE)
    //       record    (recordLen B, = output of SignedPeerRecordCodec::serialize)
    //
    // Used for all three PEX paths: flood (1 record), initial exchange (N records),
    // and periodic anti-entropy tick (N records).
    enum class PexAnnounceStatus : int {
        Success            = 0,
        MalformedEncoding  = -1,                                                        // truncation, bad length fields, count over cap, trailing bytes
    };

    namespace PexAnnounceCodec {

        // Upper bound on records per batch. Caps per-message decode cost —
        // each record costs one Ed25519 verify, which is not free.
        constexpr uint8_t MAX_RECORDS_PER_BATCH = 32;

        // Serialize records into a PEX_ANNOUNCE payload.
        // Records beyond MAX_RECORDS_PER_BATCH are silently truncated — caller is expected to batch responsibly.
        // Records whose SignedPeerRecordCodec::serialize fails (invalid addresses) are skipped; the written
        // count reflects the number actually serialized.
        std::vector<uint8_t> serialize(const std::vector<SignedPeerRecord>& records);

        // Deserialize and verify each record in the batch.
        // Framing errors abort and return MalformedEncoding — outRecords will be empty or partial, do not use.
        // Individual record verification failures (bad signature, future-dated timestamp) are
        // skipped silently — invalid records simply do not appear in outRecords.
        PexAnnounceStatus deserialize(std::span<const uint8_t> data, std::vector<SignedPeerRecord>& outRecords);

    } // namespace PexAnnounceCodec

} // namespace invilite::Mesh

#endif // MESH_PEX_ANNOUNCE_H