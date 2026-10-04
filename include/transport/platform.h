#pragma once

#ifndef TRANSPORT_PLATFORM_H
#define TRANSPORT_PLATFORM_H

#include <atomic>
#include <cstddef>
#include <thread>
#include <poll.h>

// Thin platform seam: every OS-specific call the library needs to drive sockets and threads lives here, so a Winsock
// implementation (roadmap F8) replaces this one file instead of touching the rest of the library.
// Not here yet: the socket I/O calls themselves (recv/send/sendmsg in Connection) and close() on failure paths.
namespace invilite::Transport::Platform {

    // Switches a socket (or pipe end) to non-blocking mode. False on failure.
    bool setNonBlocking(int handle);

    // Waits for readiness on several sockets — poll() on POSIX (WSAPoll() on Windows). Same contract as poll().
    int waitForSockets(pollfd* sockets, size_t count, int timeoutMs);

    // Names a thread for debuggers and top. No-op where a thread cannot be named from outside (macOS).
    void setThreadName(std::thread& thread, const char* name);

    // Wakes a thread blocked in waitForSockets(): that thread polls readHandle() for POLLIN.
    // POSIX: a non-blocking pipe (Windows will need a loopback socket pair — F8).
    class WakeupSignal {
    public:
        WakeupSignal() = default;
        ~WakeupSignal();
        WakeupSignal(const WakeupSignal&)            = delete;
        WakeupSignal& operator=(const WakeupSignal&) = delete;

        void open();                                                                    // throws std::runtime_error on failure
        void close();                                                                   // idempotent; call only after every waiting thread has stopped
        void notify() const;                                                            // never blocks; a full pipe already means "woken"
        void drain() const;                                                             // consumes pending notifications
        [[nodiscard]] int readHandle() const { return this->readEnd.load(std::memory_order_acquire); }

    private:
        std::atomic<int> readEnd{-1};                                                   // atomics: notify() may run on any thread
        std::atomic<int> writeEnd{-1};
    };

} // namespace invilite::Transport::Platform

#endif // TRANSPORT_PLATFORM_H
