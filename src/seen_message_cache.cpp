#include "meshlink/seen_message_cache.h"

#include <algorithm>

namespace invilite::Mesh {

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
