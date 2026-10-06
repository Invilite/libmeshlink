// Transport layer: TcpServer / TcpClient on top of the platform seam (poll, wakeup signal).
#include <gtest/gtest.h>
#include "transport/TcpClient.h"
#include "transport/TcpServer.h"
#include "transport/platform.h"
#include "test_helpers.h"

#include <atomic>
#include <fcntl.h>
#include <filesystem>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace invilite::Transport;
using invilite::Mesh::TestHelpers::pickUnusedPort;
using invilite::Mesh::TestHelpers::SynBlackhole;
using namespace std::chrono_literals;

namespace {

size_t countOpenFileDescriptors() {
    return static_cast<size_t>(std::distance(std::filesystem::directory_iterator("/proc/self/fd"), std::filesystem::directory_iterator{}));
}

// Loopback listener whose only accept-queue slot is taken: the kernel drops further SYNs, so a connect to it hangs
// until the caller's timeout — the one case where TcpClient really waits in poll().
struct BlackholeListener {
    int      listener = ::socket(AF_INET, SOCK_STREAM, 0);
    int      filler   = ::socket(AF_INET, SOCK_STREAM, 0);
    uint16_t port     = 0;

    BlackholeListener() {
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        ::listen(listener, 0);
        socklen_t len = sizeof(addr);
        ::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len);
        port = ntohs(addr.sin_port);
        ::connect(filler, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    }
    ~BlackholeListener() { ::close(filler); ::close(listener); }
};

// Occupies descriptors until the next one the process gets is at least `minimum`, so the code under test works with
// a high-numbered socket. Released on destruction.
struct HighDescriptorFloor {
    std::vector<int> held;
    explicit HighDescriptorFloor(int minimum) {
        while (true) {
            const int fd = ::open("/dev/null", O_RDONLY);
            if (fd < 0) break;
            held.push_back(fd);
            if (fd >= minimum) break;
        }
    }
    ~HighDescriptorFloor() { for (const int fd : held) ::close(fd); }
};

uint16_t localPortOf(int socket) {
    sockaddr_storage address{};
    socklen_t length = sizeof(address);
    ::getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length);
    return ntohs(reinterpret_cast<sockaddr_in*>(&address)->sin_port);
}

// Sends `text` on one socket and reads it back from the other (blocking sockets)
bool carries(int from, int to, const std::string& text) {
    if (::send(from, text.data(), text.size(), 0) != static_cast<ssize_t>(text.size())) return false;
    std::string received(text.size(), '\0');
    size_t got = 0;
    while (got < text.size()) {
        const ssize_t n = ::recv(to, received.data() + got, text.size() - got, 0);
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    return received == text;
}

void makeBlocking(int socket) { ::fcntl(socket, F_SETFL, ::fcntl(socket, F_GETFL, 0) & ~O_NONBLOCK); }

} // namespace

// R8: select() is undefined for descriptors >= FD_SETSIZE (1024) — FD_SET writes past the fd_set and corrupts memory.
// With poll() a high-numbered socket must behave exactly like a low one: connect succeeds, and a hanging connect
// times out cleanly.
TEST(TcpClientTest, WorksWithDescriptorsAboveSelectLimit) {
    HighDescriptorFloor floor(1100);
    if (floor.held.empty() || floor.held.back() < 1100) GTEST_SKIP() << "cannot open enough descriptors (RLIMIT_NOFILE)";

    const uint16_t serverPort = pickUnusedPort();
    TcpServer listening("127.0.0.1", serverPort, 16);
    std::atomic<int> accepted{0};
    listening.onConnect([&](int fd, const sockaddr_storage*) { ++accepted; ::close(fd); });
    ASSERT_TRUE(listening.start());

    TcpClient client;
    ASSERT_EQ(client.connect("127.0.0.1", serverPort, 2s), ConnectError::None);
    const int fd = client.release();
    EXPECT_GE(fd, 1100);
    ::close(fd);

    BlackholeListener blackhole;
    TcpClient hanging;
    const auto start = std::chrono::steady_clock::now();
    EXPECT_EQ(hanging.connect("127.0.0.1", blackhole.port, 1s), ConnectError::TimedOut);
    EXPECT_GE(std::chrono::steady_clock::now() - start, 900ms);

    listening.stop();
}

// R8: stop() wakes the listener explicitly instead of relying on shutdown() of the listening socket waking poll()
// (Linux does, macOS/BSD may not). It must return promptly, not after the 500 ms safety timeout.
TEST(TcpServerTest, StopReturnsPromptly) {
    TcpServer server("127.0.0.1", pickUnusedPort(), 16);
    ASSERT_TRUE(server.start());
    std::this_thread::sleep_for(50ms);                                                        // let the listener enter poll()

    const auto start = std::chrono::steady_clock::now();
    server.stop();
    EXPECT_LT(std::chrono::steady_clock::now() - start, 250ms);
}

// R8: the epoll descriptor used to leak on every start/stop. Restarting the server must not grow the descriptor table.
TEST(TcpServerTest, RestartDoesNotLeakDescriptors) {
    TcpServer server("127.0.0.1", pickUnusedPort(), 16);
    ASSERT_TRUE(server.start());
    server.stop();
    const size_t baseline = countOpenFileDescriptors();

    for (int i = 0; i < 20; ++i) {
        ASSERT_TRUE(server.start());
        server.stop();
    }
    EXPECT_EQ(countOpenFileDescriptors(), baseline);
}

// One readiness event can cover several queued connections; all of them must be accepted, none left waiting.
TEST(TcpServerTest, AcceptsEveryQueuedConnection) {
    const uint16_t port = pickUnusedPort();
    TcpServer server("127.0.0.1", port, 64);
    std::atomic<int> accepted{0};
    server.onConnect([&](int fd, const sockaddr_storage*) { ++accepted; ::close(fd); });
    ASSERT_TRUE(server.start());

    std::vector<TcpClient> clients(20);
    for (auto& client : clients) ASSERT_EQ(client.connect("127.0.0.1", port, 2s), ConnectError::None);

    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (accepted.load() < 20 && std::chrono::steady_clock::now() < deadline) std::this_thread::sleep_for(10ms);
    EXPECT_EQ(accepted.load(), 20);

    server.stop();
}

// Destroying a running server must stop its thread (a joinable std::thread in the destructor would terminate).
TEST(TcpServerTest, DestructorStopsRunningServer) {
    auto server = std::make_unique<TcpServer>("127.0.0.1", pickUnusedPort(), 16);
    ASSERT_TRUE(server->start());
    server.reset();
    SUCCEED();
}

// P7: transport no longer logs — a failed start reports what failed and the errno, the caller decides how to log it.
TEST(TcpServerTest, StartOnTakenPortReportsBind) {
    const uint16_t port = pickUnusedPort();
    TcpServer first("127.0.0.1", port, 16);
    ASSERT_TRUE(first.start());

    TcpServer second("127.0.0.1", port, 16);
    const ListenStartResult result = second.start();
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error, ListenError::Bind);
    EXPECT_EQ(result.errorNumber, EADDRINUSE);
    EXPECT_EQ(listenErrorName(result.error), "bind");
}

TEST(TcpServerTest, StartOnNonNumericAddressReportsInvalidAddress) {
    TcpServer server("localhost", pickUnusedPort(), 16);
    EXPECT_EQ(server.start().error, ListenError::InvalidAddress);
}

TEST(TcpClientTest, ResolveFailureIsReported) {
    TcpClient client;
    const ConnectError error = client.connect("no-such-host.invalid", 1, 1s);
    EXPECT_EQ(error, ConnectError::ResolveFailed);
    EXPECT_EQ(connectErrorName(error), "address resolution failed");
}

TEST(TcpClientTest, ExceptionFromConnectCallbackReachesCaller) {
    const uint16_t port = pickUnusedPort();
    TcpServer server("127.0.0.1", port, 16);
    server.onConnect([](int fd, const sockaddr_storage*) { ::close(fd); });
    ASSERT_TRUE(server.start());

    TcpClient client;
    client.onConnect([](int, const sockaddr_storage*) { throw std::runtime_error("callback failed"); });
    EXPECT_THROW(client.connect("127.0.0.1", port, 2s), std::runtime_error);
}

// F7-a: hole punching dials from the local port of an existing connection (to the coordinating neighbor). A and B open
// towards each other at once; both get one connection between the same two ports, and A's existing connection keeps
// working (different four-tuple).
TEST(TcpClientTest, SimultaneousOpenFromPortOfExistingConnection) {
    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddress{};
    serverAddress.sin_family      = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(listener, reinterpret_cast<sockaddr*>(&serverAddress), sizeof(serverAddress)), 0);
    ASSERT_EQ(::listen(listener, 4), 0);

    TcpClient existing;                                                                 // A's connection to the neighbor
    ASSERT_EQ(existing.connect("127.0.0.1", localPortOf(listener), 2s), ConnectError::None);
    const int existingSocket = existing.release();
    const int neighborSide   = ::accept(listener, nullptr, nullptr);
    ASSERT_GE(neighborSide, 0);
    makeBlocking(existingSocket);

    const uint16_t portA = localPortOf(existingSocket);
    const uint16_t portB = pickUnusedPort();
    SynBlackhole natA(portA), natB(portB);                                              // whichever SYN comes first is dropped

    TcpClient a, b;
    ConnectError resultA = ConnectError::None;
    std::thread sideA([&] { resultA = a.connectSimultaneous(portA, "127.0.0.1", portB, 3s); });
    const ConnectError resultB = b.connectSimultaneous(portB, "127.0.0.1", portA, 3s);
    sideA.join();
    ASSERT_EQ(resultA, ConnectError::None);
    ASSERT_EQ(resultB, ConnectError::None);

    const int socketA = a.release(), socketB = b.release();
    makeBlocking(socketA);
    makeBlocking(socketB);
    EXPECT_EQ(localPortOf(socketA), portA);
    EXPECT_EQ(localPortOf(socketB), portB);
    EXPECT_TRUE(carries(socketA, socketB, "punched"));
    EXPECT_TRUE(carries(socketB, socketA, "both ways"));
    EXPECT_TRUE(carries(existingSocket, neighborSide, "still alive"));
    EXPECT_TRUE(carries(neighborSide, existingSocket, "and back"));

    for (const int fd : { socketA, socketB, existingSocket, neighborSide, listener }) ::close(fd);
}

// A port held by a socket that did not opt into reuse cannot be borrowed — reported, not hidden
TEST(TcpClientTest, SimultaneousOpenFromPortWithoutReuseReportsBind) {
    const int holder = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(holder, reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);

    TcpClient client;
    const ConnectError error = client.connectSimultaneous(localPortOf(holder), "127.0.0.1", pickUnusedPort(), 1s);
    EXPECT_EQ(error, ConnectError::BindFailed);
    EXPECT_EQ(connectErrorName(error), "local port bind failed");
    ::close(holder);
}

TEST(TcpClientTest, SimultaneousOpenRejectsHostName) {
    TcpClient client;
    EXPECT_EQ(client.connectSimultaneous(pickUnusedPort(), "localhost", 1, 1s), ConnectError::ResolveFailed);
}

// F7: keepalive is set on a real TCP socket as asked — the kernel then keeps NAT mappings of idle links alive
TEST(PlatformTest, KeepaliveOptionsAreApplied) {
    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(listener, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);
    ASSERT_EQ(::listen(listener, 1), 0);
    socklen_t length = sizeof(address);
    ASSERT_EQ(::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length), 0);
    const int client = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_EQ(::connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);

    ASSERT_TRUE(invilite::Transport::Platform::enableKeepalive(client, 60, 15, 4));
    int value = 0;
    socklen_t size = sizeof(value);
    ASSERT_EQ(::getsockopt(client, SOL_SOCKET, SO_KEEPALIVE, &value, &size), 0);
    EXPECT_EQ(value, 1);
    ASSERT_EQ(::getsockopt(client, IPPROTO_TCP, TCP_KEEPIDLE, &value, &size), 0);
    EXPECT_EQ(value, 60);
    ASSERT_EQ(::getsockopt(client, IPPROTO_TCP, TCP_KEEPINTVL, &value, &size), 0);
    EXPECT_EQ(value, 15);
    ASSERT_EQ(::getsockopt(client, IPPROTO_TCP, TCP_KEEPCNT, &value, &size), 0);
    EXPECT_EQ(value, 4);
    ::close(client);
    ::close(listener);
}
