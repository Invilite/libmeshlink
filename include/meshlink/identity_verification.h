#pragma once

#ifndef MESH_IDENTITY_VERIFICATION_H
#define MESH_IDENTITY_VERIFICATION_H

#include "meshlink/peer_identity.h"
#include "meshlink/identity.h"
#include "meshlink/connection.h"
#include <chrono>
#include <cstdint>
#include <string_view>

using std::chrono::milliseconds;

namespace invilite::Mesh {

// Per-message flags carried by MSG1 / MSG2. Part of the signed payload, so the verifier sees exactly what the sender
// signed.
// Bit 0: probe; the connection is closed after the handshake and the remote must not be registered as a regular peer.
// Bits 1-7: reserved, sent as 0; receivers ignore unknown bits.
struct IdentityFlags {
    uint8_t raw = 0;

    bool probe() const { return (this->raw & 0x01) != 0; }
    void setProbe(bool v) { if (v) this->raw |= 0x01; else this->raw &= ~0x01; }

    bool operator==(const IdentityFlags& other) const { return this->raw == other.raw; }
};

enum class VerificationResult : uint8_t {
    Success,
    Timeout,
    InvalidSignature,
    InvalidPeerID,
    ConnectionError,
    InvalidMessage,
};

enum class VerificationStep : uint8_t { None, Msg1, Msg2, Msg3 };

// Verification does not log: the caller logs the outcome with its own context.
struct VerificationOutcome {
    VerificationResult result;
    VerificationStep   failedAt = VerificationStep::None;
};

std::string_view verificationResultName(VerificationResult result);
std::string_view verificationStepName(VerificationStep step);

class IdentityVerification {
public:
    // Initiator side. `flagsSelf` is signed into the handshake (probe=true to check reachability without joining the
    // peer pool). On success `remoteFlagsOut` holds the responder's flags (currently always 0). Blocks up to `timeout`.
    static VerificationOutcome runAsInitiator(
        Connection& conn,
        const LocalIdentity& selfIdentity,
        std::string_view nodeName,
        IdentityFlags flagsSelf,
        PeerIdentity& remoteIdentity,
        IdentityFlags& remoteFlagsOut,
        std::chrono::milliseconds timeout = std::chrono::seconds(3));

    // Responder side. Always replies with flags 0. `remoteFlagsOut` holds the initiator's flags, so the caller can tell
    // a probe from a normal connection. Blocks up to `timeout`.
    static VerificationOutcome runAsResponder(
        Connection& conn,
        const LocalIdentity& selfIdentity,
        std::string_view nodeName,
        PeerIdentity& remoteIdentity,
        IdentityFlags& remoteFlagsOut,
        std::chrono::milliseconds timeout = std::chrono::seconds(3));

private:
    static constexpr std::string_view DOMAIN = "MeshLink-IdentityVerification-V1";

    static constexpr size_t NONCE_SIZE     = 16;
    static constexpr size_t FLAGS_SIZE     = 1;
    static constexpr size_t PUBKEY_SIZE    = 32;
    static constexpr size_t SIGNATURE_SIZE = 64;
    static constexpr size_t NAME_SIZE      = 40;

    static constexpr size_t MSG1_SIZE = NONCE_SIZE + FLAGS_SIZE + PUBKEY_SIZE + PUBKEY_SIZE + NAME_SIZE;                          // 121
    static constexpr size_t MSG2_SIZE = NONCE_SIZE + FLAGS_SIZE + PUBKEY_SIZE + PUBKEY_SIZE + SIGNATURE_SIZE + NAME_SIZE;          // 185
    static constexpr size_t MSG3_SIZE = SIGNATURE_SIZE;                                                                            // 64

    // Signed payload: DOMAIN + nonce_other + flags_self + EdPub_self + XPub_self + name_self
    static std::vector<uint8_t> buildSignPayload(
        std::span<const uint8_t> nonceOther,
        IdentityFlags            flagsSelf,
        std::span<const uint8_t> ed25519PubSelf,
        std::span<const uint8_t> x25519PubSelf,
        std::span<const uint8_t> nameSelf
    );

    static bool verifySignature(
        std::span<const uint8_t> ed25519PubRemote,
        std::span<const uint8_t> payload,
        std::span<const uint8_t> signature
    );

    static std::array<uint8_t, NAME_SIZE> packName(std::string_view name);

    static PeerIdentity buildPeerIdentity(
        std::span<const uint8_t> ed25519Pub,
        std::span<const uint8_t> x25519Pub,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> name
    );
};

} // namespace invilite::Mesh

#endif // MESH_IDENTITY_VERIFICATION_H