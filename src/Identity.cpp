#include "meshlink/identity.h"

#include <botan/ed25519.h>
#include <botan/x25519.h>
#include <botan/pubkey.h>
#include <botan/hash.h>
#include <botan/auto_rng.h>

#include <fstream>
#include <stdexcept>

namespace invilite::Mesh {

    static constexpr std::array<uint8_t, 8> fileMagic = {
            'M', 'E', 'S', 'H', 'I', 'D', 0x01, 0x00
    };

    LocalIdentity LocalIdentity::generate() {
        Botan::AutoSeeded_RNG rng;
        LocalIdentity id;

        const Botan::Ed25519_PrivateKey ed25519Key(rng);
        auto edPriv = ed25519Key.raw_private_key_bits();
        id.ed25519Priv.assign(edPriv.begin(), edPriv.end());
        auto edPub = ed25519Key.raw_public_key_bits();
        id.ed25519Pub.assign(edPub.begin(), edPub.end());

        const Botan::X25519_PrivateKey x25519Key(rng);
        auto xPriv = x25519Key.raw_private_key_bits();
        id.x25519Priv.assign(xPriv.begin(), xPriv.end());
        auto xPub = x25519Key.raw_public_key_bits();
        id.x25519Pub.assign(xPub.begin(), xPub.end());

        id.peerId = derivePeerId(edPub, xPub);
        return id;
    }

    LocalIdentity LocalIdentity::load(const std::filesystem::path& keyFile) {
        std::ifstream file(keyFile, std::ios::binary);
        if (!file) throw std::runtime_error("LocalIdentity: unable to open key file: " + keyFile.string());

        std::array<uint8_t, 8> magic{};
        file.read(reinterpret_cast<char*>(magic.data()), magic.size());
        if (magic != fileMagic) throw std::runtime_error("LocalIdentity: invalid key file format.");

        LocalIdentity id;
        id.ed25519Priv.resize(64);
        id.ed25519Pub.resize(32);
        id.x25519Priv.resize(32);
        id.x25519Pub.resize(32);

        file.read(reinterpret_cast<char*>(id.ed25519Priv.data()), 64);
        file.read(reinterpret_cast<char*>(id.ed25519Pub.data()),  32);
        file.read(reinterpret_cast<char*>(id.x25519Priv.data()),  32);
        file.read(reinterpret_cast<char*>(id.x25519Pub.data()),   32);

        if (!file) throw std::runtime_error("LocalIdentity: key file is truncated or corrupted.");

        id.peerId = derivePeerId(id.ed25519Pub, id.x25519Pub);
        return id;
    }

    void LocalIdentity::save(const std::filesystem::path& keyFile) const {
        if (keyFile.has_parent_path()) std::filesystem::create_directories(keyFile.parent_path());

        std::ofstream file(keyFile, std::ios::binary | std::ios::trunc);
        if (!file) throw std::runtime_error("LocalIdentity: unable to write key file: " + keyFile.string());

        file.write(reinterpret_cast<const char*>(fileMagic.data()),   fileMagic.size());
        file.write(reinterpret_cast<const char*>(ed25519Priv.data()), ed25519Priv.size());
        file.write(reinterpret_cast<const char*>(ed25519Pub.data()),  ed25519Pub.size());
        file.write(reinterpret_cast<const char*>(x25519Priv.data()),  x25519Priv.size());
        file.write(reinterpret_cast<const char*>(x25519Pub.data()),   x25519Pub.size());

        std::filesystem::permissions(keyFile,
                                     std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace);
    }

    std::vector<uint8_t> LocalIdentity::sign(std::span<const uint8_t> data) const {
        Botan::AutoSeeded_RNG rng;
        const Botan::Ed25519_PrivateKey key = Botan::Ed25519_PrivateKey::from_seed(
                std::span<const uint8_t>(ed25519Priv.data(), 32)
        );

        Botan::PK_Signer signer(key, rng, "Pure");
        signer.update(data.data(), data.size());
        return signer.signature(rng);
    }

    SignedPeerRecord LocalIdentity::buildSelfRecord(const std::vector<PeerAddress>& addresses) const {
        const auto now = std::chrono::system_clock::now();

        // Serialize the to-be-signed portion. Returns empty on invalid address strings:
        // treat that as a hard configuration error (caller misconfigured announcedAddresses).
        const std::vector<uint8_t> toSign = SignedPeerRecordCodec::serializeForSigning(
                ed25519Pub, x25519Pub, now, addresses
        );
        if (toSign.empty()) {
            throw std::runtime_error("LocalIdentity::buildSelfRecord: failed to serialize record (invalid addresses?)");
        }

        SignedPeerRecord rec;
        rec.peerId     = peerId;
        rec.ed25519Pub = ed25519Pub;
        rec.x25519Pub  = x25519Pub;
        rec.createdAt  = now;
        rec.addresses  = addresses;
        rec.signature  = sign(toSign);
        return rec;
    }

    PeerId LocalIdentity::derivePeerId(std::span<const uint8_t> ed25519Pub, std::span<const uint8_t> x25519Pub) {
        const auto hash = Botan::HashFunction::create_or_throw("BLAKE2b(256)");
        hash->update(ed25519Pub.data(), ed25519Pub.size());
        hash->update(x25519Pub.data(),  x25519Pub.size());
        const auto out = hash->final();

        PeerId id;
        std::copy_n(out.begin(), id.size(), id.begin());
        return id;
    }

} // namespace invilite::Mesh