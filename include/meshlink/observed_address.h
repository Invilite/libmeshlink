#pragma once

#ifndef MESH_OBSERVED_ADDRESS_H
#define MESH_OBSERVED_ADDRESS_H

#include "meshlink/peer_identity.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace invilite::Mesh {

    // OBSERVED_ADDRESS (0xFF/0x0002): "this is the IP I see you connecting from", sent by the accepting side right after
    // HELLO. Payload: family(1: 4 or 6) + address(4 or 16 bytes). The port is left out: it is the NAT's mapping, not a
    // listening port.
    namespace ObservedAddressCodec {
        std::vector<uint8_t>       encode(const std::string& address);              // empty when `address` is not an IP
        std::optional<std::string> decode(std::span<const uint8_t> payload);       // exact length, known family
    }

    struct ObservedSelfAddress {
        std::string                             address;
        PeerId                                  reportedBy{};
        std::chrono::system_clock::time_point   reportedAt;
    };

} // namespace invilite::Mesh

#endif // MESH_OBSERVED_ADDRESS_H
