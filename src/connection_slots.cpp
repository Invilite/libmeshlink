#include "meshlink/connection_slots.h"

#include <utility>

invilite::Mesh::ConnectionSlots::Slot::Slot(ConnectionSlots* owner, const bool inbound, std::string address)
    : owner(owner), inbound(inbound), address(std::move(address)) {}

invilite::Mesh::ConnectionSlots::Slot::~Slot() {
    this->release();
}

invilite::Mesh::ConnectionSlots::Slot::Slot(Slot&& other) noexcept
    : owner(std::exchange(other.owner, nullptr)), inbound(other.inbound), address(std::move(other.address)) {}

invilite::Mesh::ConnectionSlots::Slot& invilite::Mesh::ConnectionSlots::Slot::operator=(Slot&& other) noexcept {
    if (this != &other) {
        this->release();
        this->owner   = std::exchange(other.owner, nullptr);
        this->inbound = other.inbound;
        this->address = std::move(other.address);
    }
    return *this;
}

void invilite::Mesh::ConnectionSlots::Slot::release() {
    if (this->owner) std::exchange(this->owner, nullptr)->giveBack(this->inbound, this->address);
}

bool invilite::Mesh::ConnectionSlots::inboundHasRoom(const uint16_t hard) const {
    std::lock_guard lock(this->mutex);
    return this->inboundTotal < hard;
}

std::optional<invilite::Mesh::ConnectionSlots::Slot> invilite::Mesh::ConnectionSlots::tryTakeInbound(const std::string& address, const uint16_t hard, const uint16_t perAddress) {
    std::lock_guard lock(this->mutex);
    if (this->inboundTotal >= hard) return std::nullopt;

    uint16_t& fromAddress = this->inboundByAddress[address];
    if (fromAddress >= perAddress) {
        if (fromAddress == 0) this->inboundByAddress.erase(address);                       // only when perAddress == 0 — keep the map clean
        return std::nullopt;
    }

    ++fromAddress;
    ++this->inboundTotal;
    return Slot(this, true, address);
}

std::optional<invilite::Mesh::ConnectionSlots::Slot> invilite::Mesh::ConnectionSlots::tryTakeOutbound(const uint16_t hard) {
    std::lock_guard lock(this->mutex);
    if (this->outboundTotal >= hard) return std::nullopt;
    ++this->outboundTotal;
    return Slot(this, false, {});
}

size_t invilite::Mesh::ConnectionSlots::inboundInUse() const {
    std::lock_guard lock(this->mutex);
    return this->inboundTotal;
}

size_t invilite::Mesh::ConnectionSlots::outboundInUse() const {
    std::lock_guard lock(this->mutex);
    return this->outboundTotal;
}

void invilite::Mesh::ConnectionSlots::giveBack(const bool inbound, const std::string& address) {
    std::lock_guard lock(this->mutex);
    if (!inbound) {
        --this->outboundTotal;
        return;
    }
    --this->inboundTotal;
    const auto it = this->inboundByAddress.find(address);
    if (it != this->inboundByAddress.end() && --it->second == 0) this->inboundByAddress.erase(it);   // no entry per address ever seen — bounded by live connections
}
