#pragma once

#ifndef MESH_IDENTITY_H
#define MESH_IDENTITY_H

#include "meshlink/peer_identity.h"
#include "meshlink/signed_peer_record.h"

#include <filesystem>
#include <span>

namespace invilite::Mesh {

    // LocalIdentity — own identity with full key material (private + public).
    // Distinct from PeerIdentity (public-only, used for remote peers).
    // All cryptographic operations that require our private keys live here:
    //   - sign() for low-level Ed25519 signing
    //   - buildSelfRecord() for constructing signed peer records (HELLO content)
    // Future: signing routed messages, decrypting E2E payloads addressed to us.
    class LocalIdentity final : public PeerIdentity {
    public:
        // ── Lifecycle ──
        static LocalIdentity generate();
        static LocalIdentity load(const std::filesystem::path& keyFile);
        void                 save(const std::filesystem::path& keyFile) const;

        // ── Crypto operations using private keys ──
        [[nodiscard]] std::vector<uint8_t> sign(std::span<const uint8_t> data) const;

        // Build a self-attested signed record — used to construct HELLO content.
        // Throws on serialization failure (e.g. malformed addresses).
        [[nodiscard]] SignedPeerRecord buildSelfRecord(const std::vector<PeerAddress>& addresses) const;

        // ── Static helper ──
        static PeerId derivePeerId(std::span<const uint8_t> ed25519Pub, std::span<const uint8_t> x25519Pub);

        // ── Accessors for private keys ──
        [[nodiscard]] const std::vector<uint8_t>& getEd25519Priv() const { return ed25519Priv; }
        [[nodiscard]] const std::vector<uint8_t>& getX25519Priv()  const { return x25519Priv; }

    private:
        LocalIdentity() = default;

        // Private keys (seeds/scalars)
        std::vector<uint8_t> ed25519Priv;
        std::vector<uint8_t> x25519Priv;
    };

} // namespace invilite::Mesh

#endif // MESH_IDENTITY_H