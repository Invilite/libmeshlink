#ifndef MESH_WIRE_BYTES_H
#define MESH_WIRE_BYTES_H

// Big-endian writers and a bounds-checked reader shared by the Router's wire codecs (router_wire, state_report_wire).
// Private to the library: not installed with the public headers.

#include "meshlink/peer_identity.h"

#include <cstdint>
#include <span>
#include <vector>

namespace invilite::Mesh::WireBytes {

    constexpr size_t PEER_ID_SIZE = 32;

    inline void writeBE16(std::vector<uint8_t>& out, uint16_t v) {
        out.push_back(static_cast<uint8_t>(v >> 8));
        out.push_back(static_cast<uint8_t>(v));
    }

    inline void writeBE32(std::vector<uint8_t>& out, uint32_t v) {
        for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(v >> shift));
    }

    inline void writeBE64(std::vector<uint8_t>& out, uint64_t v) {
        for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(v >> shift));
    }

    inline void writePeerId(std::vector<uint8_t>& out, const PeerId& id) {
        out.insert(out.end(), id.begin(), id.end());
    }

    // Bounds-checked sequential reader over a received span. Every read fails (returns false) instead of overrunning.
    class WireReader {
    public:
        explicit WireReader(std::span<const uint8_t> data) : data(data) {}

        size_t remaining() const { return data.size() - offset; }

        bool readBytes(size_t count, std::span<const uint8_t>& out) {
            if (count > remaining()) return false;
            out = data.subspan(offset, count);
            offset += count;
            return true;
        }

        bool readU8(uint8_t& out) {
            if (remaining() < 1) return false;
            out = data[offset++];
            return true;
        }

        bool readUnsignedBE(size_t width, uint64_t& out) {
            if (remaining() < width) return false;
            out = 0;
            for (size_t i = 0; i < width; ++i) out = (out << 8) | data[offset++];
            return true;
        }

        bool readPeerId(PeerId& out) {
            std::span<const uint8_t> bytes;
            if (!readBytes(PEER_ID_SIZE, bytes)) return false;
            std::copy(bytes.begin(), bytes.end(), out.begin());
            return true;
        }

        bool readPeerIds(size_t count, std::vector<PeerId>& out) {
            if (count > remaining() / PEER_ID_SIZE) return false;                   // check before allocating
            out.resize(count);
            for (PeerId& id : out) readPeerId(id);
            return true;
        }

    private:
        std::span<const uint8_t> data;
        size_t                   offset = 0;
    };

} // namespace invilite::Mesh::WireBytes

#endif // MESH_WIRE_BYTES_H
