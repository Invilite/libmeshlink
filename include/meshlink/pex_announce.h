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
    // Used for the flood (1 record), the initial exchange and the periodic anti-entropy tick (N records).
    enum class PexAnnounceStatus : int {
        Success            = 0,
        MalformedEncoding  = -1,                                                        // truncation, bad length fields, count over cap, trailing bytes
    };

    namespace PexAnnounceCodec {

        // Caps per-message decode cost: each record costs one Ed25519 verify.
        constexpr uint8_t MAX_RECORDS_PER_BATCH = 32;

        // Records beyond MAX_RECORDS_PER_BATCH are silently truncated; the caller batches.
        // Records whose SignedPeerRecordCodec::serialize fails (invalid addresses) are skipped; the written
        // count reflects the number actually serialized.
        std::vector<uint8_t> serialize(const std::vector<SignedPeerRecord>& records);

        // Verifies each record. A framing error returns MalformedEncoding and outRecords must not be used.
        // A record that fails verification (bad signature, future-dated timestamp) is skipped silently.
        PexAnnounceStatus deserialize(std::span<const uint8_t> data, std::vector<SignedPeerRecord>& outRecords);

    } // namespace PexAnnounceCodec

    // PEX_REQUEST payload format (group 0xFF / subtype 0x0021), "send me the records of these peers":
    //
    //   count        (1B, 1..MAX_RECORDS_PER_BATCH, so the reply fits one PEX_ANNOUNCE)
    //   count * PeerId (32B)
    //
    // The reply is an ordinary PEX_ANNOUNCE carrying the records the responder has; unknown ids are left out.
    // Used by the Router to fetch the key of a broadcast sender it does not know yet.
    namespace PexRequestCodec {

        // Empty vector when `wanted` is empty or longer than MAX_RECORDS_PER_BATCH.
        std::vector<uint8_t> serialize(const std::vector<PeerId>& wanted);

        // MalformedEncoding on count 0, count over the cap, truncation or trailing bytes.
        PexAnnounceStatus deserialize(std::span<const uint8_t> data, std::vector<PeerId>& outWanted);

    } // namespace PexRequestCodec

} // namespace invilite::Mesh

#endif // MESH_PEX_ANNOUNCE_H