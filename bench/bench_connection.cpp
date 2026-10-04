// Frame throughput of Connection: pure frame crypto (encrypt on one side, decrypt on the other) and the full
// send() → socket → receive() path over loopback. Build: make bench; run: ./run_bench
#include "meshlink/connection.h"

#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace invilite::Mesh;
using namespace std::chrono;

namespace {

// Exposes the frame crypto for measuring it without the socket.
class MeasuredConnection : public Connection {
public:
    using Connection::Connection;
    using Connection::encryptData;
    using Connection::decryptData;
};

struct Pair {
    std::array<uint8_t, 64>             secret{};
    std::unique_ptr<MeasuredConnection> client, server;

    Pair() {
        secret.fill(0x5A);
        const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        ::listen(listener, 1);
        socklen_t len = sizeof(addr);
        ::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len);
        const int clientFd = ::socket(AF_INET, SOCK_STREAM, 0);
        ::connect(clientFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        sockaddr_storage peer{};
        socklen_t peerLen = sizeof(peer);
        const int serverFd = ::accept(listener, reinterpret_cast<sockaddr*>(&peer), &peerLen);
        ::close(listener);
        sockaddr_storage clientView{};
        std::memcpy(&clientView, &addr, sizeof(addr));
        client = std::make_unique<MeasuredConnection>(clientFd, &clientView, &secret, 64 * 1024 * 1024);
        server = std::make_unique<MeasuredConnection>(serverFd, &peer, &secret);
        if (client->initHandshake() != 0 || server->waitForHandshake(milliseconds(2000)) <= 0 || client->waitForHandshake(milliseconds(2000)) != 0) {
            std::fprintf(stderr, "handshake failed\n");
            std::exit(1);
        }
    }
};

double cpuSeconds() { timespec t{}; ::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t); return static_cast<double>(t.tv_sec) + static_cast<double>(t.tv_nsec) / 1e9; }

void measureCrypto(Pair& pair, size_t payloadSize, size_t frames) {
    const std::vector<uint8_t> payload(payloadSize, 0x42);
    const auto start = steady_clock::now();
    size_t check = 0;
    for (size_t i = 0; i < frames; ++i) {
        const auto frame = pair.client->encryptData(payload);
        const auto plain = pair.server->decryptData(frame);
        check += plain.size();
    }
    const double seconds = duration<double>(steady_clock::now() - start).count();
    if (check != payloadSize * frames) std::fprintf(stderr, "mismatch\n");
    std::printf("crypto     %6zu B  %8.0f ns/frame  %8.1f MB/s\n", payloadSize, seconds * 1e9 / static_cast<double>(frames), static_cast<double>(payloadSize * frames) / seconds / 1e6);
}

void measureEndToEnd(Pair& pair, size_t payloadSize, size_t frames) {
    const std::vector<uint8_t> payload(payloadSize, 0x42);
    size_t received = 0;
    const double cpuStart = cpuSeconds();
    const auto start = steady_clock::now();
    std::thread reader([&] {
        std::vector<uint8_t> message;
        while (received < frames) {
            if (pair.server->receive(message, milliseconds(100)) > 0) ++received;
        }
    });
    for (size_t sent = 0; sent < frames; ) {
        if (pair.client->send(&payload) > 0) ++sent;
        else pair.client->drainSendQueue(milliseconds(100));                             // queue full — let the socket catch up
        if (pair.client->hasQueuedFrames()) pair.client->writeQueuedFrames();
    }
    pair.client->drainSendQueue(seconds(10));
    reader.join();
    const double seconds = duration<double>(steady_clock::now() - start).count();
    const double cpu     = cpuSeconds() - cpuStart;
    std::printf("send→recv  %6zu B  %8.0f ns/frame  %8.1f MB/s  cpu %6.0f ns/frame\n", payloadSize, seconds * 1e9 / static_cast<double>(frames),
                static_cast<double>(payloadSize * frames) / seconds / 1e6, cpu * 1e9 / static_cast<double>(frames));
}

} // namespace

int main() {
    Pair pair;
    for (const auto& [size, frames] : std::vector<std::pair<size_t, size_t>>{ { 64, 200000 }, { 1024, 200000 }, { 16384, 40000 } }) measureCrypto(pair, size, frames);
    for (const auto& [size, frames] : std::vector<std::pair<size_t, size_t>>{ { 64, 200000 }, { 1024, 200000 }, { 16384, 40000 } }) measureEndToEnd(pair, size, frames);
    return 0;
}
