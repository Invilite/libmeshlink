#pragma once

#ifndef MESH_THREAD_SAFE_QUEUE_H
#define MESH_THREAD_SAFE_QUEUE_H

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>
#include <utility>

namespace invilite::Mesh {

// Thread-safe FIFO queue with optional blocking wait and shutdown support.
// Designed for single- and multi-producer, single-consumer use patterns,
// but works correctly under any producer/consumer arrangement.
template<typename T>
class ThreadSafeQueue {
public:
    ThreadSafeQueue() = default;

    ThreadSafeQueue(const ThreadSafeQueue&)            = delete;
    ThreadSafeQueue& operator=(const ThreadSafeQueue&) = delete;

    // Non-blocking push. Always succeeds (unbounded).
    void push(T item) {
        {
            std::lock_guard lock(this->mutex);
            this->queue.push(std::move(item));
        }
        this->cv.notify_one();
    }

    // Non-blocking pop. Returns false if queue is empty.
    bool tryPop(T& out) {
        std::lock_guard lock(this->mutex);
        if (this->queue.empty()) return false;
        out = std::move(this->queue.front());
        this->queue.pop();
        return true;
    }

    // Blocking pop with timeout. Returns nullopt on timeout or shutdown.
    std::optional<T> waitPop(std::chrono::milliseconds timeout) {
        std::unique_lock lock(this->mutex);
        const bool ready = this->cv.wait_for(lock, timeout, [this] {
            return !this->queue.empty() || this->shuttingDown;
        });
        if (!ready)                                return std::nullopt;             // timeout
        if (this->shuttingDown && this->queue.empty()) return std::nullopt;         // woken by shutdown, nothing pending

        T item = std::move(this->queue.front());
        this->queue.pop();
        return item;
    }

    // Wake all waiters — they will return nullopt if queue is empty.
    // Does not clear the queue; remaining items can still be tryPop'd.
    void shutdown() {
        {
            std::lock_guard lock(this->mutex);
            this->shuttingDown = true;
        }
        this->cv.notify_all();
    }

    size_t size() const {
        std::lock_guard lock(this->mutex);
        return this->queue.size();
    }

    bool empty() const {
        std::lock_guard lock(this->mutex);
        return this->queue.empty();
    }

private:
    mutable std::mutex              mutex;
    std::condition_variable         cv;
    std::queue<T>                   queue;
    bool                            shuttingDown = false;
};

} // namespace invilite::Mesh

#endif // MESH_THREAD_SAFE_QUEUE_H