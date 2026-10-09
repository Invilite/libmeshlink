#pragma once

#ifndef MESH_HOLE_PUNCH_PARTICIPANT_H
#define MESH_HOLE_PUNCH_PARTICIPANT_H

#include "meshlink/hole_punch_wire.h"

#include <chrono>
#include <map>
#include <utility>
#include <optional>
#include <vector>

namespace invilite::Mesh {

    struct HolePunchParticipantConfig {
        std::chrono::milliseconds   exchangeTimeout = std::chrono::seconds(10);      // asked / accepted -> NOW at the latest
        std::chrono::milliseconds   punchWindow     = std::chrono::seconds(4);       // simultaneous connect after NOW (SYN retransmits at ~0, 1, 3 s)
        // Rest for a pair after consecutive failed punches, the last step repeating: a symmetric NAT or CGNAT rarely
        // changes, but sometimes does, so the pair is checked again after a while, never written off
        std::vector<std::chrono::seconds> failureRest = { std::chrono::seconds(30), std::chrono::seconds(60), std::chrono::seconds(120),
                                                          std::chrono::seconds(300), std::chrono::seconds(600), std::chrono::seconds(1800) };
    };

    // Only the node with the smaller PeerId asks for a punch, so the asking side is always the handshake initiator once
    // TCP is up, whether the socket came from connect() or (rarely) from accept()
    [[nodiscard]] inline bool holePunchInitiatesHandshake(const PeerId& self, const PeerId& peer) { return self < peer; }

    // A punch to start now: connect from the local port of our connection with `via` to `remoteEndpoint`
    struct HolePunchStart {
        PeerId                                  peer{};
        PeerId                                  via{};
        HolePunchEndpoint                       remoteEndpoint;
        bool                                    initiatesHandshake = false;
        std::chrono::steady_clock::time_point   deadline{};
    };

    // An exchange that ended without a punch. `reason` empty: no answer in time.
    struct HolePunchFailure {
        PeerId                                  peer{};
        PeerId                                  via{};
        std::optional<HolePunchDeclineReason>   reason;
    };

    // Both punching sides: A asks a common neighbor, B answers its offer, both start on NOW.
    // A NOW starts nothing unless it names an exchange agreed with that same neighbor, and only once. At most one exchange
    // per peer. A pair whose punches failed rests (failureRest): A does not ask, B declines with TooManyAttempts. Decides only: Network sends the messages, checks slots and existing connections, runs the punch.
    // Not thread-safe: owned by the Management thread. Time comes in as `now`; the nonce is drawn by the caller.
    class HolePunchParticipant {
    public:
        HolePunchParticipant(const PeerId& self, HolePunchParticipantConfig config = {});

        // A: the PUNCH_REQUEST to send to `via`, or nothing when `target` may not be asked (larger PeerId, exchange running,
        // pair resting)
        std::optional<HolePunchMessage> request(const PeerId& target, const PeerId& via, const HolePunchNonce& nonce, std::chrono::steady_clock::time_point now);

        // B: PUNCH_OFFER from neighbor `from`. `localObstacle`: a reason Network already has to refuse (no slot, connected).
        // Returns the accept or decline for `from`; nothing for a replayed nonce.
        std::optional<HolePunchMessage> onOffer(const PeerId& from, const HolePunchOffer& offer, std::optional<HolePunchDeclineReason> localObstacle,
                                                std::chrono::steady_clock::time_point now);

        // Both: PUNCH_NOW from `from`: the punch to start, at most once per exchange
        std::optional<HolePunchStart> onNow(const PeerId& from, const HolePunchNow& message, std::chrono::steady_clock::time_point now);

        // Both: PUNCH_DECLINE from `from` ends its exchange
        std::optional<HolePunchFailure> onDecline(const PeerId& from, const HolePunchDecline& decline, std::chrono::steady_clock::time_point now);

        // Neighbor `peer` left: exchanges coordinated by it that did not start punching fail with PeerLeft
        std::vector<HolePunchFailure> onNeighborLost(const PeerId& peer);

        // The punch with `peer` ended: a new exchange with it may start. A failure (no connection, wrong identity) makes
        // the pair rest; a success forgets earlier failures.
        void finishPunch(const PeerId& peer, bool connected, std::chrono::steady_clock::time_point now);

        // A failed exchange that never reached punching but tells something about the pair (no common neighbor, no answer)
        void recordFailedAttempt(const PeerId& peer, std::chrono::steady_clock::time_point now);

        // Exchanges past their deadline are forgotten; those that never got a NOW are returned as failures
        std::vector<HolePunchFailure> expire(std::chrono::steady_clock::time_point now);

        [[nodiscard]] bool isExchangingWith(const PeerId& peer) const;
        [[nodiscard]] bool isResting(const PeerId& peer, std::chrono::steady_clock::time_point now) const;

    private:
        enum class Stage { Asked, Accepted, Punching, Ended };

        struct Exchange {
            PeerId                                  peer{};
            PeerId                                  via{};
            Stage                                   stage = Stage::Asked;
            std::chrono::steady_clock::time_point   deadline{};
        };

        const PeerId                                self;
        const HolePunchParticipantConfig            config;
        std::map<HolePunchNonce, Exchange>          exchanges;                      // ended ones stay until deadline: their nonce is not reused
        std::map<PeerId, std::pair<size_t, std::chrono::steady_clock::time_point>> pairFailures;   // consecutive failures, rest until
    };

} // namespace invilite::Mesh

#endif // MESH_HOLE_PUNCH_PARTICIPANT_H
