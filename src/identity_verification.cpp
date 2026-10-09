#include "meshlink/identity_verification.h"
#include "meshlink/identity.h"

#include <botan/ed25519.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>

#include <cstring>
#include <stdexcept>
#include <algorithm>

namespace invilite::Mesh {

// -- Helpers ------------------------------------------------------------------

std::array<uint8_t, IdentityVerification::NAME_SIZE> IdentityVerification::packName(std::string_view name) {
    std::array<uint8_t, NAME_SIZE> packed{};
    const size_t len = std::min(name.size(), NAME_SIZE - 1);
    std::memcpy(packed.data(), name.data(), len);
    return packed;
}

std::vector<uint8_t> IdentityVerification::buildSignPayload(
    std::span<const uint8_t> nonceOther,
    IdentityFlags            flagsSelf,
    std::span<const uint8_t> ed25519PubSelf,
    std::span<const uint8_t> x25519PubSelf,
    std::span<const uint8_t> nameSelf)
{
    // Signed payload layout:
    //   DOMAIN || nonce_other || flags_self || EdPub_self || XPub_self || name_self
    // flags_self is part of the signature so that a man-in-the-middle cannot flip the probe bit
    // (or any future bit) in flight: the verifier recomputes this exact payload.
    std::vector<uint8_t> payload;
    payload.reserve(DOMAIN.size() + nonceOther.size() + FLAGS_SIZE
                    + ed25519PubSelf.size() + x25519PubSelf.size() + nameSelf.size());

    payload.insert(payload.end(), DOMAIN.begin(),        DOMAIN.end());
    payload.insert(payload.end(), nonceOther.begin(),    nonceOther.end());
    payload.push_back(flagsSelf.raw);
    payload.insert(payload.end(), ed25519PubSelf.begin(), ed25519PubSelf.end());
    payload.insert(payload.end(), x25519PubSelf.begin(), x25519PubSelf.end());
    payload.insert(payload.end(), nameSelf.begin(),      nameSelf.end());

    return payload;
}

bool IdentityVerification::verifySignature(
    std::span<const uint8_t> ed25519PubRemote,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> signature)
{
    try {
        const Botan::Ed25519_PublicKey key(
            std::vector<uint8_t>(ed25519PubRemote.begin(), ed25519PubRemote.end())
        );
        Botan::PK_Verifier verifier(key, "Pure");
        verifier.update(payload.data(), payload.size());
        return verifier.check_signature(signature.data(), signature.size());
    } catch (const std::exception&) {
        return false;
    }
}

PeerIdentity IdentityVerification::buildPeerIdentity(
    std::span<const uint8_t> ed25519Pub,
    std::span<const uint8_t> x25519Pub,
    std::span<const uint8_t> signature,
    std::span<const uint8_t> name)
{
    PeerIdentity pi;
    pi.peerId = LocalIdentity::derivePeerId(ed25519Pub, x25519Pub);

    pi.ed25519Pub.assign(ed25519Pub.begin(), ed25519Pub.end());
    pi.x25519Pub.assign(x25519Pub.begin(), x25519Pub.end());
    pi.signature.assign(signature.begin(), signature.end());

    std::memcpy(pi.name.data(), name.data(), std::min(name.size(), pi.name.size()));

    return pi;
}

// -- Initiator ----------------------------------------------------------------

std::string_view verificationResultName(VerificationResult result) {
    switch (result) {
        case VerificationResult::Success:          return "success";
        case VerificationResult::Timeout:          return "timeout";
        case VerificationResult::InvalidSignature: return "invalid signature";
        case VerificationResult::InvalidPeerID:    return "invalid peer id";
        case VerificationResult::ConnectionError:  return "connection error";
        case VerificationResult::InvalidMessage:   return "invalid message";
    }
    return "unknown";
}

std::string_view verificationStepName(VerificationStep step) {
    switch (step) {
        case VerificationStep::None: return "-";
        case VerificationStep::Msg1: return "MSG1";
        case VerificationStep::Msg2: return "MSG2";
        case VerificationStep::Msg3: return "MSG3";
    }
    return "unknown";
}

VerificationOutcome IdentityVerification::runAsInitiator(
    Connection& conn,
    const LocalIdentity& selfIdentity,
    std::string_view nodeName,
    IdentityFlags flagsSelf,
    PeerIdentity& remoteIdentity,
    IdentityFlags& remoteFlagsOut,
    std::chrono::milliseconds timeout)
{
    Botan::AutoSeeded_RNG rng;

    // Default output: overwritten on success. Keeps caller state deterministic on early return.
    remoteFlagsOut = IdentityFlags{};

    // -- Msg1: send our intro --------------------------------------------------
    //   nonce_I (16) || flags_I (1) || EdPub_I (32) || XPub_I (32) || name_I (40) = 121B
    std::array<uint8_t, NONCE_SIZE> nonceI{};
    rng.randomize(nonceI.data(), nonceI.size());

    const std::array<uint8_t, NAME_SIZE> packedName = packName(nodeName);

    std::vector<uint8_t> msg1;
    msg1.reserve(MSG1_SIZE);
    msg1.insert(msg1.end(), nonceI.begin(),                         nonceI.end());
    msg1.push_back(flagsSelf.raw);                                                  // NEW: our intent for this session
    msg1.insert(msg1.end(), selfIdentity.getEd25519Pub().begin(),   selfIdentity.getEd25519Pub().end());
    msg1.insert(msg1.end(), selfIdentity.getX25519Pub().begin(),    selfIdentity.getX25519Pub().end());
    msg1.insert(msg1.end(), packedName.begin(),                     packedName.end());

    // send() never blocks and may leave part of the message queued; the I/O thread does not own this connection yet,
    // so this worker pushes it out itself (blocking is fine on an ephemeral handshake thread).
    if (conn.send(&msg1) <= 0 || !conn.drainSendQueue(timeout)) {
        return {VerificationResult::ConnectionError, VerificationStep::Msg1};
    }

    // -- Msg2: receive responder's intro + signature ---------------------------
    //   nonce_R (16) || flags_R (1) || EdPub_R (32) || XPub_R (32) || sig_R (64) || name_R (40) = 185B
    std::vector<uint8_t> msg2;
    const ssize_t received = conn.receive(msg2, timeout);

    if (received == 0) return {VerificationResult::Timeout, VerificationStep::Msg2};
    if (received < 0)  return {VerificationResult::ConnectionError, VerificationStep::Msg2};
    if (msg2.size() < MSG2_SIZE) return {VerificationResult::InvalidMessage, VerificationStep::Msg2};

    const uint8_t* ptr = msg2.data();
    std::span<const uint8_t> nonceR      (ptr, NONCE_SIZE);      ptr += NONCE_SIZE;
    const IdentityFlags      flagsR{ *ptr };                     ptr += FLAGS_SIZE; // NEW
    std::span<const uint8_t> ed25519PubR (ptr, PUBKEY_SIZE);     ptr += PUBKEY_SIZE;
    std::span<const uint8_t> x25519PubR  (ptr, PUBKEY_SIZE);     ptr += PUBKEY_SIZE;
    std::span<const uint8_t> sigR        (ptr, SIGNATURE_SIZE);  ptr += SIGNATURE_SIZE;
    std::span<const uint8_t> nameR       (ptr, NAME_SIZE);

    // Verify responder's signature: payload must include their flags byte to prevent bit-flipping.
    const std::vector<uint8_t> payloadR = buildSignPayload(nonceI, flagsR, ed25519PubR, x25519PubR, nameR);
    if (!verifySignature(ed25519PubR, payloadR, sigR)) {
        return {VerificationResult::InvalidSignature, VerificationStep::Msg2};
    }

    // -- Msg3: send our signature ----------------------------------------------
    // Our signature covers our own flags (flagsSelf), matching what we sent in MSG1.
    const std::vector<uint8_t> payloadI = buildSignPayload(
        nonceR,
        flagsSelf,
        selfIdentity.getEd25519Pub(),
        selfIdentity.getX25519Pub(),
        packedName
    );

    const std::vector<uint8_t> sigI = selfIdentity.sign(payloadI);

    std::vector<uint8_t> msg3(sigI.begin(), sigI.end());
    if (conn.send(&msg3) <= 0 || !conn.drainSendQueue(timeout)) {
        return {VerificationResult::ConnectionError, VerificationStep::Msg3};
    }

    remoteIdentity = buildPeerIdentity(ed25519PubR, x25519PubR, sigR, nameR);
    remoteFlagsOut = flagsR;
    return {VerificationResult::Success};
}

// -- Responder ----------------------------------------------------------------

VerificationOutcome IdentityVerification::runAsResponder(
        Connection& conn,
        const LocalIdentity& selfIdentity,
        std::string_view nodeName,
        PeerIdentity& remoteIdentity,
        IdentityFlags& remoteFlagsOut,
        std::chrono::milliseconds timeout)
{
    Botan::AutoSeeded_RNG rng;
    remoteFlagsOut = IdentityFlags{};

    // -- Msg1: receive initiator's intro ---------------------------------------
    std::vector<uint8_t> msg1;
    const ssize_t received = conn.receive(msg1, timeout);

    if (received == 0) return {VerificationResult::Timeout, VerificationStep::Msg1};
    if (received < 0)  return {VerificationResult::ConnectionError, VerificationStep::Msg1};
    if (msg1.size() < MSG1_SIZE) return {VerificationResult::InvalidMessage, VerificationStep::Msg1};

    const uint8_t* ptr = msg1.data();
    std::span<const uint8_t> nonceI      (ptr, NONCE_SIZE);  ptr += NONCE_SIZE;
    const IdentityFlags      flagsI{ *ptr };                 ptr += FLAGS_SIZE;
    std::span<const uint8_t> ed25519PubI (ptr, PUBKEY_SIZE); ptr += PUBKEY_SIZE;
    std::span<const uint8_t> x25519PubI  (ptr, PUBKEY_SIZE); ptr += PUBKEY_SIZE;
    std::span<const uint8_t> nameI       (ptr, NAME_SIZE);

    // -- Msg2: send our intro + signature -------------------------------------
    const IdentityFlags flagsSelf{};

    std::array<uint8_t, NONCE_SIZE> nonceR{};
    rng.randomize(nonceR.data(), nonceR.size());

    const std::array<uint8_t, NAME_SIZE> packedName = packName(nodeName);

    const std::vector<uint8_t> payloadR = buildSignPayload(
            nonceI, flagsSelf,
            selfIdentity.getEd25519Pub(), selfIdentity.getX25519Pub(), packedName
    );
    const std::vector<uint8_t> sigR = selfIdentity.sign(payloadR);

    std::vector<uint8_t> msg2;
    msg2.reserve(MSG2_SIZE);
    msg2.insert(msg2.end(), nonceR.begin(),                        nonceR.end());
    msg2.push_back(flagsSelf.raw);
    msg2.insert(msg2.end(), selfIdentity.getEd25519Pub().begin(),  selfIdentity.getEd25519Pub().end());
    msg2.insert(msg2.end(), selfIdentity.getX25519Pub().begin(),   selfIdentity.getX25519Pub().end());
    msg2.insert(msg2.end(), sigR.begin(),                          sigR.end());
    msg2.insert(msg2.end(), packedName.begin(),                    packedName.end());

    if (conn.send(&msg2) <= 0 || !conn.drainSendQueue(timeout)) return {VerificationResult::ConnectionError, VerificationStep::Msg2};

    // -- Msg3: receive initiator's signature -----------------------------------
    std::vector<uint8_t> msg3;
    const ssize_t received3 = conn.receive(msg3, timeout);

    if (received3 == 0) return {VerificationResult::Timeout, VerificationStep::Msg3};
    if (received3 < 0)  return {VerificationResult::ConnectionError, VerificationStep::Msg3};
    if (msg3.size() < MSG3_SIZE) return {VerificationResult::InvalidMessage, VerificationStep::Msg3};

    const std::vector<uint8_t> payloadI = buildSignPayload(nonceR, flagsI, ed25519PubI, x25519PubI, nameI);
    if (!verifySignature(ed25519PubI, payloadI, msg3)) {
        return {VerificationResult::InvalidSignature, VerificationStep::Msg3};
    }

    remoteIdentity = buildPeerIdentity(ed25519PubI, x25519PubI, msg3, nameI);
    remoteFlagsOut = flagsI;
    return {VerificationResult::Success};
}

} // namespace invilite::Mesh