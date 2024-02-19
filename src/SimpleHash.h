#ifndef SIMPLE_HASH_H
#define SIMPLE_HASH_H

#include <array>
#include <cstddef>

struct SimpleHash {
    std::size_t operator()(const std::array<uint8_t, 16>& key) const {
        std::size_t hash = 0;
        for (auto byte: key) {
            hash ^= (hash << 5) + (hash >> 2) + byte;
        }
        return hash;
    }
};

#endif