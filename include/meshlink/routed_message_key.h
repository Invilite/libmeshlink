#pragma once

#ifndef MESH_ROUTED_MESSAGE_KEY_H
#define MESH_ROUTED_MESSAGE_KEY_H

#include "meshlink/peer_identity.h"

#include <cstddef>
#include <cstdint>

namespace invilite::Mesh {

    // Identity of a routed message: msgId is random per sender, so the pair is unique network-wide. Duplicate memory,
    // Plumtree announcements (IHAVE / GRAFT) and the GRAFT cache all key by it — never by msgId alone, which another
    // sender could reuse to shadow a genuine message (docs/router.md 3.3).
    struct RoutedMessageKey {
        PeerId      sender{};
        uint64_t    msgId = 0;

        bool operator==(const RoutedMessageKey&) const = default;
    };

    // Seeded per process: msgId is chosen by the sender, so a plain hash would let a hostile sender put every key in one bucket
    struct RoutedMessageKeyHash {
        size_t operator()(const RoutedMessageKey& key) const noexcept;
    };

} // namespace invilite::Mesh

#endif // MESH_ROUTED_MESSAGE_KEY_H
