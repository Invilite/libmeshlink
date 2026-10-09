#pragma once

#ifndef MESH_IDENTITY_H
#define MESH_IDENTITY_H

#include "meshlink/peer_identity.h"
#include "meshlink/signed_peer_record.h"

#include <filesystem>
#include <span>

namespace invilite::Mesh {

    // Our own identity with the private keys; PeerIdentity is the public-only view of a remote peer.
    // Every operation that needs a private key lives here.
    class LocalIdentity final : public PeerIdentity {
    public:
        static LocalIdentity generate();
        static LocalIdentity load(const std::filesystem::path& keyFile);
        void                 save(const std::filesystem::path& keyFile) const;

        [[nodiscard]] std::vector<uint8_t> sign(std::span<const uint8_t> data) const;

        // Builds the self-signed record sent in HELLO. Throws on serialization failure (e.g. malformed addresses).
        [[nodiscard]] SignedPeerRecord buildSelfRecord(const std::vector<PeerAddress>& addresses) const;

        static PeerId derivePeerId(std::span<const uint8_t> ed25519Pub, std::span<const uint8_t> x25519Pub);

        [[nodiscard]] const std::vector<uint8_t>& getEd25519Priv() const { return ed25519Priv; }
        [[nodiscard]] const std::vector<uint8_t>& getX25519Priv()  const { return x25519Priv; }

    private:
        LocalIdentity() = default;

        std::vector<uint8_t> ed25519Priv;
        std::vector<uint8_t> x25519Priv;
    };

} // namespace invilite::Mesh

#endif // MESH_IDENTITY_H