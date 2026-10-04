#pragma once

#ifndef MESH_NETWORK_EVENTS_H
#define MESH_NETWORK_EVENTS_H

#include "meshlink/peer_identity.h"

#include <cstdint>
#include <vector>

namespace invilite::Mesh {

// Message delivered to listeners via onMessageReceived. Group 0x00..0xFE only —
// internal management messages (group 0xFF) are handled inside Network and never surfaced.
    struct NetworkMessage {
        PeerId                  source{};
        uint8_t                 group   = 0;                                            // 0x00..0xFE
        uint16_t                subtype = 0;
        std::vector<uint8_t>    payload;
    };

// Observer interface for Network lifecycle and message events.
//
// Threading contract:
//   - onPeerConnected / onPeerDisconnected fire on Network's I/O thread.
//   - onMessageReceived fires on Network's Dispatch thread.
//   - Listeners MUST be fast and non-blocking. The expected pattern is to enqueue the
//     event into the listener's own thread-safe queue and return immediately. Long-running
//     work (signature verification, decryption, business logic) belongs in the listener's
//     own thread.
//   - Listeners MUST NOT call back into Network methods that would acquire the same locks
//     transitively (no defined cases today, but keep work minimal).
//
// All methods have empty default implementations — listeners override only the events
// they care about.
//
// Lifetime: Network holds shared_ptr to each registered listener. Caller can release
// their handle after addListener; Network keeps the listener alive until removeListener
// is called or Network is destroyed.
//
// Shutdown semantics: peers torn down by Network::stop() do NOT generate onPeerDisconnected.
// Listeners should treat Network shutdown as implicit disconnection of all peers.
    class NetworkEventListener {
    public:
        virtual ~NetworkEventListener() = default;

        // Fired when a peer becomes Active in the connected set, after handshake and identity
        // verification have completed. The PeerIdentity carries the verified public keys and
        // name, immediately usable for cryptographic operations targeting this peer.
        virtual void onPeerConnected(const PeerIdentity& identity) { (void)identity; }

        // Fired when a peer is removed from the connected set (remote disconnect, GOODBYE,
        // socket error, tie-break loss).
        virtual void onPeerDisconnected(const PeerId& peerId) { (void)peerId; }

        // Fired for each non-internal frame (group != 0xFF) received from a peer.
        virtual void onMessageReceived(const NetworkMessage& msg) { (void)msg; }
    };

} // namespace invilite::Mesh

#endif // MESH_NETWORK_EVENTS_H