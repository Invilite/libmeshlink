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

// Thread-safe FIFO queue; any number of producers and consumers. waitPop blocks, so call it only from threads that may.
template<typename T>
class ThreadSafeQueue {
public:
    ThreadSafeQueue() = default;

    ThreadSafeQueue(const ThreadSafeQueue&)            = delete;
    ThreadSafeQueue& operator=(const ThreadSafeQueue&) = delete;

    // Never blocks; the queue is unbounded.
    void push(T item) {
        {
            std::lock_guard lock(this->mutex);
            this->queue.push(std::move(item));
        }
        this->cv.notify_one();
    }

    // Never blocks; false when the queue is empty.
    bool tryPop(T& out) {
        std::lock_guard lock(this->mutex);
        if (this->queue.empty()) return false;
        out = std::move(this->queue.front());
        this->queue.pop();
        return true;
    }

    // Blocks up to `timeout`. Returns nullopt on timeout, or on shutdown with nothing queued.
    std::optional<T> waitPop(std::chrono::milliseconds timeout) {
        std::unique_lock lock(this->mutex);
        const bool ready = this->cv.wait_for(lock, timeout, [this] {
            return !this->queue.empty() || this->shuttingDown;
        });
        if (!ready)                                return std::nullopt;
        if (this->shuttingDown && this->queue.empty()) return std::nullopt;

        T item = std::move(this->queue.front());
        this->queue.pop();
        return item;
    }

    // Wakes all waiters; they return nullopt once the queue is empty. Queued items stay and can still be tryPop'd.
    void shutdown() {
        {
            std::lock_guard lock(this->mutex);
            this->shuttingDown = true;
        }
        this->cv.notify_all();
    }

    // Accept waiters again after shutdown() (Network::start() after stop()). Leftover items are dropped.
    void reopen() {
        std::lock_guard lock(this->mutex);
        this->shuttingDown = false;
        this->queue = {};
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