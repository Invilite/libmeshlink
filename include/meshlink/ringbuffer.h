#pragma once

#ifndef LIBMESHLINK_RINGBUFFER_H
#define LIBMESHLINK_RINGBUFFER_H

#include <vector>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <stdexcept>

namespace invilite::Mesh {

template<typename T> class RingBuffer {
public:

    /**
     * @param maxSize Maximal amount of *T* elements that buffer can hold.
     * @param softLimit If set to other that 0, buffer with try to shrink his capacity to that amount of *T* elements.
     */
    explicit RingBuffer(const uint32_t maxSize, const uint32_t softLimit = 0):
        buffer(1), softLimit(softLimit), maxSize(maxSize), currentSize(0), head(0), tail(0) {}

    ~RingBuffer() = default;

    /**
     * @brief Inserts T elements at the back of the buffer.
     * @return If the buffer is not full, add an elements at the back position and returns *true*,
     * if the buffer is full or new data is too big return false.
     */
    bool push_back(const T* data, size_t count) {
        if (count == 0) return true;
        if (currentSize + count > maxSize) return false;

        ensure_capacity(currentSize + count);

        const size_t available_to_end = buffer.size() - tail;
        if (count <= available_to_end) {
            std::copy(data, data + count, buffer.begin() + tail);
            tail += count;
        } else {
            std::copy(data, data + available_to_end, buffer.begin() + tail);
            const size_t remaining = count - available_to_end;
            std::copy(data + available_to_end, data + count, buffer.begin());
            tail = remaining;
        }

        currentSize += count;
        return true;
    }

    bool push_back(const std::vector<T>& data) {
        return push_back(data.data(), data.size());
    }

    /**
     * @brief Remove *count* elements from the front of the buffer.
     * @return The amount of elements removed (if any).
     */
    size_t pop_front(size_t count) {
        if (count == 0) return 0;
        if (count > currentSize) count = currentSize;

        head = (head + count) % buffer.size();
        currentSize -= count;

        if (currentSize == 0) {
            head = tail = 0;
        }

        shrink_if_needed();
        return count;
    }

    /**
     * @brief Checks if buffer is empty.
     * @return *true* if buffer is empty, *false* otherwise.
     */
    bool empty() const {
        return currentSize == 0;
    }

    /**
     * @brief Checks if buffer is full.
     * @return *true* if buffer is full, *false* otherwise.
     */
    bool full() const {
        return currentSize == maxSize;
    }

    /**
     * @brief Removes all content of the buffer.
     */
    void clear() {
        currentSize = 0;
        head = 0;
        tail = 0;
        shrink_if_needed();
    }

    /**
     * @brief Return current buffer size in *T* elements.
     * @return current buffer size.
     */
    size_t size() const {
        return currentSize;
    }

    /**
     * @brief Reserve space in buffer for specific elements count.
     */
    void reserve(size_t count) {
        if (count <= buffer.size()) return;
        size_t new_capacity = std::min(static_cast<size_t>(maxSize), count);
        reorganize_buffer(new_capacity);
    }

    /**
     * @brief Returns buffer capacity in elements count.
     * @return buffer current capacity.
     */
    size_t capacity() const {
        return buffer.size();
    }

    /**
     * @brief Gets the n'th element from the buffer starts
     * @param offset
     * @return Pointer to the element
     */
    const T* at(size_t offset) const {
        if (offset >= currentSize) return nullptr;
        return &buffer[(head + offset) % buffer.size()];
    }

    /**
     * @brief Copy data from buffer to external variable
     *
     * @param dest
     * @param count
     * @param offset
     * @return
     */
    size_t copy(std::vector<T>& dest, size_t count, size_t offset = 0) const {
        if (offset >= currentSize) return 0;

        count = std::min(count, currentSize - offset);
        dest.resize(count);

        size_t source_pos = (head + offset) % buffer.size();
        for (size_t i = 0; i < count; ++i) {
            dest[i] = buffer[source_pos];
            source_pos = (source_pos + 1) % buffer.size();
        }

        return count;
    }

    /**
     * @brief Extract data as vector from buffer
     * @param offset Starting position
     * @param count Number of elements to extract
     * @return Vector containing requested data
     */
    std::vector<T> get(size_t offset, size_t count) const {
        std::vector<T> result;
        copy(result, count, offset);
        return result;
    }

    /**
     * @brief Extract data as std::array if count is known at compile time
     * @tparam N Number of elements to extract
     * @param offset Starting position
     * @return Array containing requested data
     */
    template<size_t N>
    std::array<T, N> get_array(size_t offset = 0) const {
        if (offset + N > currentSize) {
            throw std::out_of_range("Requested range exceeds buffer size");
        }

        std::array<T, N> result;
        size_t source_pos = (head + offset) % buffer.size();
        for (size_t i = 0; i < N; ++i) {
            result[i] = buffer[source_pos];
            source_pos = (source_pos + 1) % buffer.size();
        }
        return result;
    }

    /**
     * @brief Get contiguous data segments for zero-copy access
     * @return Pair of pointer and size for first segment, second segment follows if needed
     */
    std::pair<const T*, size_t> contiguous_data() const {
        if (empty()) return {nullptr, 0};

        if (head < tail) {
            return {buffer.data() + head, tail - head};
        } else {
            return {buffer.data() + head, buffer.size() - head};
        }
    }

    std::pair<const T*, size_t> contiguous_data2() const {
        if (empty() || head < tail) {
            return {nullptr, 0};
        } else {
            return {buffer.data(), tail};
        }
    }

    /**
     * @brief Make buffer data contiguous in memory
     */
    void make_contiguous() {
        if (empty() || head == 0) return;
        reorganize_buffer(buffer.size());
    }

protected:
    void ensure_capacity(size_t required_capacity) {
        if (required_capacity <= buffer.size()) return;

        size_t new_capacity = buffer.size();
        while (new_capacity < required_capacity && new_capacity < maxSize) {
            new_capacity = std::min(static_cast<size_t>(maxSize), new_capacity * 2);
        }

        if (new_capacity < required_capacity) {
            return;
        }

        reorganize_buffer(new_capacity);
    }

    void reorganize_buffer(size_t new_capacity) {
        std::vector<T> new_buffer(new_capacity);

        if (currentSize > 0) {
            auto [data1, size1] = contiguous_data();
            auto [data2, size2] = contiguous_data2();

            std::copy(data1, data1 + size1, new_buffer.begin());
            if (size2 > 0) {
                std::copy(data2, data2 + size2, new_buffer.begin() + size1);
            }
        }

        buffer = std::move(new_buffer);
        head = 0;
        tail = currentSize;
    }

    void shrink_if_needed() {
        if (softLimit == 0) return;

        if (buffer.size() > softLimit && currentSize < buffer.size() / 4) {
            size_t new_capacity = std::max(static_cast<size_t>(softLimit), currentSize * 2);
            if (new_capacity < buffer.size()) {
                reorganize_buffer(new_capacity);
            }
        } else if (buffer.size() > softLimit && currentSize == 0) {
            reorganize_buffer(softLimit);
        }
    }

private:
    std::vector<T> buffer;
    const uint32_t softLimit;
    const uint32_t maxSize;
    size_t currentSize;             // Liczba elementów w buforze
    size_t head;                    // Początek danych
    size_t tail;                    // Koniec danych (pierwszy wolny bajt)
};

} // namespace invilite::Mesh

#endif //LIBMESHLINK_RINGBUFFER_H