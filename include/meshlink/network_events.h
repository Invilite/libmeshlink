#pragma once

#ifndef MESH_NETWORK_EVENTS_H
#define MESH_NETWORK_EVENTS_H

#include "meshlink/peer_identity.h"

#include <cstdint>
#include <vector>

namespace invilite::Mesh {

// Message delivered to listeners via onMessageReceived. Group 0x00..0xFE only:
// internal management messages (group 0xFF) are handled inside Network and never surfaced.
    struct NetworkMessage {
        PeerId                  source{};
        uint8_t                 group   = 0;
        uint16_t                subtype = 0;
        std::vector<uint8_t>    payload;
    };

// Observer interface for Network lifecycle and message events.
//
// Threading contract:
//   - All events fire on Network's I/O thread, so a listener sees each peer's events in
//     order: connected, its messages, disconnected - never a message after the disconnect.
//   - Listeners MUST be fast and non-blocking: the I/O thread serves every peer, so a slow
//     listener stalls the whole node. Enqueue the event and return; long-running work
//     belongs in the listener's own thread.
//   - Listeners may call sendToPeer, getters and addListener / removeListener, but never
//     Network::stop(): it joins the I/O thread the listener runs on.
//
// Lifetime: Network holds a shared_ptr to each registered listener until removeListener
// is called or Network is destroyed.
//
// Peers torn down by Network::stop() do NOT generate onPeerDisconnected; treat shutdown
// as implicit disconnection of all peers.
    class NetworkEventListener {
    public:
        virtual ~NetworkEventListener() = default;

        // Runs on the network I/O thread; must not block. Fired when a peer becomes
        // Active after handshake and identity verification; identity carries the
        // verified public keys and name.
        virtual void onPeerConnected(const PeerIdentity& identity) { (void)identity; }

        // Runs on the network I/O thread; must not block. Fired when a peer leaves the
        // connected set: remote disconnect, GOODBYE, socket error, tie-break loss.
        virtual void onPeerDisconnected(const PeerId& peerId) { (void)peerId; }

        // Runs on the network I/O thread; must not block. Fired for each frame with
        // group 0x00..0xFE received from a peer.
        virtual void onMessageReceived(const NetworkMessage& msg) { (void)msg; }
    };

} // namespace invilite::Mesh

#endif // MESH_NETWORK_EVENTS_H