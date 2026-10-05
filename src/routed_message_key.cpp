#include "meshlink/routed_message_key.h"

#include <cstring>
#include <random>

namespace invilite::Mesh {

namespace {
    // msgId is chosen by the sender, so a plain hash would let a hostile sender pick ids that all land in one bucket.
    // Mixing in a per-process random seed through a strong mixer (splitmix64 finalizer) makes buckets unpredictable.
    const uint64_t HASH_SEED = [] {
        std::random_device device;
        return (static_cast<uint64_t>(device()) << 32) ^ device();
    }();

    uint64_t mix64(uint64_t x) {
        x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL;
        x ^= x >> 27; x *= 0x94D049BB133111EBULL;
        x ^= x >> 31;
        return x;
    }
}

size_t RoutedMessageKeyHash::operator()(const RoutedMessageKey& key) const noexcept {
    uint64_t senderPrefix;
    std::memcpy(&senderPrefix, key.sender.data(), sizeof(senderPrefix));
    return static_cast<size_t>(mix64(key.msgId ^ mix64(senderPrefix ^ HASH_SEED)));
}

} // namespace invilite::Mesh
