#ifndef PACKET_OBSERVER_H
#define PACKET_OBSERVER_H

#include <vector>

class PacketObserver {
public:
    virtual ~PacketObserver() {}
    virtual void update(const std::vector<uint8_t>* data, const std::array<uint8_t, 16>* remoteNodeId) = 0;
};

#endif