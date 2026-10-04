#pragma once

#ifndef MESH_CONNECTION_SLOTS_H
#define MESH_CONNECTION_SLOTS_H

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace invilite::Mesh {

// Bookkeeping for the hard connection limits (roadmap R10/R1): every connection that holds resources — from accept()
// or the start of a dial until it is closed, handshake included — holds one Slot. A Slot gives its place back in its
// destructor, so no failure path can leak or double-release it. Pure counting: knows nothing about peers or protocol.
class ConnectionSlots {
public:
    class Slot {
    public:
        Slot() = default;
        ~Slot();
        Slot(Slot&& other) noexcept;
        Slot& operator=(Slot&& other) noexcept;
        Slot(const Slot&)            = delete;
        Slot& operator=(const Slot&) = delete;

    private:
        friend class ConnectionSlots;
        Slot(ConnectionSlots* owner, bool inbound, std::string address);
        void release();

        ConnectionSlots* owner   = nullptr;                                         // nullptr = empty (moved from)
        bool             inbound = false;
        std::string      address;                                                   // remote IP, inbound only
    };

    ConnectionSlots() = default;
    ConnectionSlots(const ConnectionSlots&)            = delete;
    ConnectionSlots& operator=(const ConnectionSlots&) = delete;

    // Inbound total is checked before the address, so above the hard limit nothing but a counter comparison happens.
    [[nodiscard]] bool inboundHasRoom(uint16_t hard) const;
    std::optional<Slot> tryTakeInbound(const std::string& address, uint16_t hard, uint16_t perAddress);
    std::optional<Slot> tryTakeOutbound(uint16_t hard);

    [[nodiscard]] size_t inboundInUse() const;
    [[nodiscard]] size_t outboundInUse() const;

private:
    void giveBack(bool inbound, const std::string& address);

    mutable std::mutex                        mutex;
    size_t                                    inboundTotal  = 0;
    size_t                                    outboundTotal = 0;
    std::unordered_map<std::string, uint16_t> inboundByAddress;
};

} // namespace invilite::Mesh

#endif // MESH_CONNECTION_SLOTS_H
