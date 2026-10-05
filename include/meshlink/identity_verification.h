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

// Per-message flags carried by IdentityVerification MSG1 / MSG2. Single byte, bit-addressed.
// Part of the signed payload, so any bit must match between sender intent and verifier view.
//
// Bit 0 : probe — sender signals this is a probe connection (will be closed after handshake).
//                 Receiver should not register the remote as a regular peer.
// Bit 1-7 : reserved (must be 0). Receivers ignore unknown bits for forward compatibility.
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

// Handshake message at which verification failed (None on success)
enum class VerificationStep : uint8_t { None, Msg1, Msg2, Msg3 };

// Result of a verification run. Verification does not log: the caller (Network) logs the outcome with its context.
struct VerificationOutcome {
    VerificationResult result;
    VerificationStep   failedAt = VerificationStep::None;
};

std::string_view verificationResultName(VerificationResult result);
std::string_view verificationStepName(VerificationStep step);

class IdentityVerification {
public:
    // Initiator side. `flagsSelf` is our intent for this session (e.g. probe=true when
    // we're validating a known peer's reachability without joining their peer pool).
    // On success, `remoteFlagsOut` receives the responder's flags byte (currently always 0,
    // but exposed for forward compatibility).
    static VerificationOutcome runAsInitiator(
        Connection& conn,
        const LocalIdentity& selfIdentity,
        std::string_view nodeName,
        IdentityFlags flagsSelf,
        PeerIdentity& remoteIdentity,
        IdentityFlags& remoteFlagsOut,
        std::chrono::milliseconds timeout = std::chrono::seconds(3));

    // Responder side. Always replies with flags_self = 0 (no responder-side signalling
    // defined yet). `remoteFlagsOut` receives the initiator's flags byte — caller uses
    // this to distinguish probe vs. normal connection and branch accordingly.
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
    static constexpr size_t FLAGS_SIZE     = 1;                                     // NEW
    static constexpr size_t PUBKEY_SIZE    = 32;
    static constexpr size_t SIGNATURE_SIZE = 64;
    static constexpr size_t NAME_SIZE      = 40;

    static constexpr size_t MSG1_SIZE = NONCE_SIZE + FLAGS_SIZE + PUBKEY_SIZE + PUBKEY_SIZE + NAME_SIZE;                          // 121
    static constexpr size_t MSG2_SIZE = NONCE_SIZE + FLAGS_SIZE + PUBKEY_SIZE + PUBKEY_SIZE + SIGNATURE_SIZE + NAME_SIZE;          // 185
    static constexpr size_t MSG3_SIZE = SIGNATURE_SIZE;                                                                            // 64

    // Build payload to sign:
    //   DOMAIN + nonce_other + flags_self + EdPub_self + XPub_self + name_self
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