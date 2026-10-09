#include "transport/platform.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <pthread.h>
#include <stdexcept>
#include <unistd.h>

bool invilite::Transport::Platform::setNonBlocking(const int handle) {
    const int flags = ::fcntl(handle, F_GETFL, 0);
    return flags != -1 && ::fcntl(handle, F_SETFL, flags | O_NONBLOCK) != -1;
}

bool invilite::Transport::Platform::disableNagle(const int socket) {
    const int enabled = 1;
    return ::setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) == 0;
}

bool invilite::Transport::Platform::enableKeepalive(const int socket, const int idleSeconds, const int intervalSeconds, const int probes) {
    const int enabled = 1;
    if (::setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled)) != 0) return false;
#if defined(TCP_KEEPIDLE)
    const int idleOption = TCP_KEEPIDLE;
#else
    const int idleOption = TCP_KEEPALIVE;                                                   // macOS name for the idle time
#endif
    return ::setsockopt(socket, IPPROTO_TCP, idleOption, &idleSeconds, sizeof(idleSeconds)) == 0
        && ::setsockopt(socket, IPPROTO_TCP, TCP_KEEPINTVL, &intervalSeconds, sizeof(intervalSeconds)) == 0
        && ::setsockopt(socket, IPPROTO_TCP, TCP_KEEPCNT, &probes, sizeof(probes)) == 0;
}

bool invilite::Transport::Platform::allowLocalPortReuse(const int socket) {
    const int enabled = 1;
    if (::setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) return false;
#if defined(SO_REUSEPORT)
    return ::setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled)) == 0;
#else
    return true;                                                                        // Windows: no SO_REUSEPORT, other SO_REUSEADDR semantics
#endif
}

int invilite::Transport::Platform::waitForSockets(pollfd* sockets, const size_t count, const int timeoutMs) {
    return ::poll(sockets, static_cast<nfds_t>(count), timeoutMs);
}

void invilite::Transport::Platform::setThreadName(std::thread& thread, const char* name) {
#if defined(__APPLE__)
    (void)thread; (void)name;                                                           // macOS can only name the calling thread
#else
    pthread_setname_np(thread.native_handle(), name);                                   // Linux: at most 15 characters
#endif
}

invilite::Transport::Platform::WakeupSignal::~WakeupSignal() {
    this->close();
}

void invilite::Transport::Platform::WakeupSignal::open() {
    this->close();
    int ends[2];
    if (::pipe(ends) == -1) throw std::runtime_error("Failed to create wakeup pipe");
    if (!setNonBlocking(ends[0]) || !setNonBlocking(ends[1])) {
        ::close(ends[0]);
        ::close(ends[1]);
        throw std::runtime_error("Failed to set wakeup pipe non-blocking");
    }
    this->readEnd.store(ends[0], std::memory_order_release);
    this->writeEnd.store(ends[1], std::memory_order_release);
}

void invilite::Transport::Platform::WakeupSignal::close() {
    const int readHandle  = this->readEnd.exchange(-1);
    const int writeHandle = this->writeEnd.exchange(-1);
    if (readHandle  != -1) ::close(readHandle);
    if (writeHandle != -1) ::close(writeHandle);
}

void invilite::Transport::Platform::WakeupSignal::notify() const {
    const int writeHandle = this->writeEnd.load(std::memory_order_acquire);
    if (writeHandle == -1) return;
    constexpr char byte = 'x';
    [[maybe_unused]] const auto written = ::write(writeHandle, &byte, 1);              // EAGAIN = pipe full = a wakeup is already pending
}

void invilite::Transport::Platform::WakeupSignal::drain() const {
    const int readHandle = this->readEnd.load(std::memory_order_acquire);
    if (readHandle == -1) return;
    char buffer[64];
    while (::read(readHandle, buffer, sizeof(buffer)) > 0) { }
}
