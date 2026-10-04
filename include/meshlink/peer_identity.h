#pragma once

#ifndef MESH_PEER_IDENTITY_H
#define MESH_PEER_IDENTITY_H

#include <vector>
#include <array>
#include <cstdint>

namespace invilite::Mesh {

    // 32-byte peer identifier
    using PeerId = std::array<uint8_t, 32>;

    class PeerIdentity {
    public:
        PeerIdentity() = default;
        virtual ~PeerIdentity() = default;

        // Public accessors for remote/local public data
        const PeerId&               getPeerId()      const { return peerId; }
        const std::vector<uint8_t>& getEd25519Pub()  const { return ed25519Pub; }
        const std::vector<uint8_t>& getX25519Pub()   const { return x25519Pub; }
        const std::array<uint8_t, 40>& getName()     const { return name; }

    protected:
        // Verification needs to populate these fields after handshake
        friend class IdentityVerification;

        PeerId                  peerId{};
        std::vector<uint8_t>    ed25519Pub;
        std::vector<uint8_t>    x25519Pub;
        std::vector<uint8_t>    signature;  // Remote's proof of identity
        std::array<uint8_t, 40> name{};     // Null-padded display name
    };

} // namespace invilite::Mesh

#endif // MESH_PEER_IDENTITY_H