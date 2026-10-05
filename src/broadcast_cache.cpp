#include "meshlink/broadcast_cache.h"

namespace invilite::Mesh {

namespace {
    RoutedMessageKey keyOf(const RoutedMessage& message) { return { message.sender, message.msgId }; }
}

BroadcastCache::BroadcastCache(std::chrono::seconds retention, size_t byteLimit) : retention(retention), byteLimit(byteLimit) {}

bool BroadcastCache::store(RoutedMessage message, std::chrono::steady_clock::time_point now) {
    this->dropExpired(now);
    const RoutedMessageKey key = keyOf(message);
    const size_t encodedBytes = RouterWire::encodedSize(message);
    if (this->byKey.contains(key) || encodedBytes > this->byteLimit) return false;

    this->makeRoom(encodedBytes);
    this->byAge.push_back({ std::move(message), encodedBytes, now, {} });
    this->byKey.emplace(key, std::prev(this->byAge.end()));
    this->totalBytes += encodedBytes;
    return true;
}

bool BroadcastCache::replace(RoutedMessage message, std::chrono::steady_clock::time_point now) {
    const auto found = this->byKey.find(keyOf(message));
    if (found == this->byKey.end()) return false;
    this->erase(found->second);                                                     // re-stored as the newest: the better copy is fresh news
    return this->store(std::move(message), now);
}

const RoutedMessage* BroadcastCache::find(const RoutedMessageKey& key) const {
    const auto found = this->byKey.find(key);
    return found == this->byKey.end() ? nullptr : &found->second->message;
}

bool BroadcastCache::markSentTo(const RoutedMessageKey& key, const PeerId& neighbor) {
    const auto found = this->byKey.find(key);
    if (found == this->byKey.end()) return false;
    return found->second->sentTo.insert(neighbor).second;
}

void BroadcastCache::forgetNeighbor(const PeerId& neighbor) {
    for (Entry& entry : this->byAge) entry.sentTo.erase(neighbor);
}

void BroadcastCache::dropExpired(std::chrono::steady_clock::time_point now) {
    while (!this->byAge.empty() && now - this->byAge.front().storedAt >= this->retention) this->erase(this->byAge.begin());
}

void BroadcastCache::makeRoom(size_t bytesNeeded) {
    while (!this->byAge.empty() && this->totalBytes + bytesNeeded > this->byteLimit) this->erase(this->byAge.begin());
}

void BroadcastCache::erase(EntryList::iterator entry) {
    this->totalBytes -= entry->encodedBytes;
    this->byKey.erase(keyOf(entry->message));
    this->byAge.erase(entry);
}

} // namespace invilite::Mesh
