#pragma once

#ifndef MESH_PEER_REACHABILITY_H
#define MESH_PEER_REACHABILITY_H

#include "meshlink/peer_directory.h"
#include "meshlink/signed_peer_record.h"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace invilite::Mesh {

    // Private, link-local, loopback, CGNAT (100.64/10) and IPv6 ULA / link-local addresses: reachable only inside the
    // network they belong to. Text that is not an IP address counts as not private.
    bool isPrivateAddress(std::string_view address);

    // Discovery policy: the addresses of a peer worth dialing or probing from here, in the record's order. A peer that
    // reached us from a public address is behind NAT (or simply elsewhere) relative to us — its private addresses lead
    // nowhere from here and are left out. Peers we meet over a private address (same LAN, VPN) keep them (R3).
    std::vector<PeerAddress> dialableAddresses(const KnownPeer& peer);

    // What a fresh HELLO says about the path to its sender: true — it reached us from a public address (NAT between us),
    // false — we met over a private address (it dialed us from one, or we reached it at an announced one), nothing — no
    // evidence (we dialed a public address). `connectedFromAddress` is empty when we dialed it.
    std::optional<bool> observedReachedUsOverPublicInternet(const std::string& connectedFromAddress, const std::string& dialedAddress, bool dialedAddressAnnounced);

} // namespace invilite::Mesh

#endif // MESH_PEER_REACHABILITY_H
