#include "meshlink/seen_message_cache.h"

#include <algorithm>
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

SeenMessageCache::SeenMessageCache(std::chrono::seconds window, size_t capacity) : window(window), capacity(capacity) {}

bool SeenMessageCache::contains(const RoutedMessageKey& key) const {
    return this->keys.contains(key);
}

bool SeenMessageCache::predatesEvictedKeys(uint32_t sentAtUnixSeconds) const {
    return this->evictedSentAtFloor && sentAtUnixSeconds <= *this->evictedSentAtFloor;
}

void SeenMessageCache::remember(const RoutedMessageKey& key, uint32_t sentAtUnixSeconds, std::chrono::steady_clock::time_point now) {
    while (!this->byAge.empty() && now - this->byAge.front().seenAt > this->window) {
        this->keys.erase(this->byAge.front().key);
        this->byAge.pop_front();
    }
    if (!this->keys.insert(key).second) return;

    this->byAge.push_back({ now, sentAtUnixSeconds, key });
    if (this->byAge.size() > this->capacity) {
        const Entry& evicted = this->byAge.front();
        this->evictedSentAtFloor = std::max(this->evictedSentAtFloor.value_or(0), evicted.sentAtUnixSeconds);
        this->keys.erase(evicted.key);
        this->byAge.pop_front();
    }
}

} // namespace invilite::Mesh
