// hello_mesh: the smallest program that is a meshlink node.
//
//   ./examples/hello_mesh 8420                    first node
//   ./examples/hello_mesh 8421 127.0.0.1:8420     second node, dials the first
//
// Each node waits for a neighbor, broadcasts one message to the whole mesh, prints what arrives and exits after 10 s.

#include <meshlink/identity.h>
#include <meshlink/network.h>
#include <meshlink/peer_directory.h>
#include <meshlink/router.h>
#include <meshlink/router_events.h>

#include <chrono>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <thread>

using namespace invilite::Mesh;

static std::optional<uint16_t> parsePort(const std::string& text) {
    if (text.empty() || text.size() > 5 || text.find_first_not_of("0123456789") != std::string::npos) return std::nullopt;
    const int port = std::stoi(text);
    return port > 0 && port <= 65535 ? std::optional<uint16_t>(port) : std::nullopt;
}

// Runs on the Router's thread: print and return, never block here.
class PrintMessages : public RouterEventListener {
public:
    void onMessageDelivered(const RoutedDelivery& delivery) override {
        const std::string text(delivery.payload.begin(), delivery.payload.end());
        std::printf("received from %02x%02x%02x%02x (%u hop(s)): %s\n", delivery.sender[0], delivery.sender[1], delivery.sender[2], delivery.sender[3], delivery.hopsTraveled, text.c_str());
    }
};

int main(int argc, char** argv) {
    const auto usage = [&] { std::fprintf(stderr, "usage: %s <port> [host:port]\n", argv[0]); return 1; };
    if (argc < 2) return usage();
    const std::optional<uint16_t> port = parsePort(argv[1]);
    std::optional<uint16_t> peerPort;
    std::string peerHost;
    if (argc > 2) {
        const std::string peer = argv[2];
        const auto colon = peer.rfind(':');
        if (colon == std::string::npos || colon == 0) return usage();
        peerHost = peer.substr(0, colon);
        peerPort = parsePort(peer.substr(colon + 1));
        if (!peerPort) return usage();
    }
    if (!port) return usage();

    // Every node of one mesh shares this 64-byte key. A real network uses a random one (meshlinkd --create-network-key).
    auto networkKey = std::make_shared<std::array<uint8_t, 64>>();
    networkKey->fill(0x42);

    // A fresh identity on every start; a real node saves it (LocalIdentity::save) and loads it next time.
    auto identity  = std::make_shared<LocalIdentity>(LocalIdentity::generate());
    auto directory = std::make_shared<PeerDirectory>();

    NetworkConfig config;
    config.listenPort = *port;
    config.nodeName   = "hello-" + std::to_string(*port);

    Network network(identity, networkKey, directory, config);
    Router  router(network, directory, identity);
    router.addListener(std::make_shared<PrintMessages>());

    network.start();
    router.start();
    if (peerPort) network.connectToPeer(peerHost, *peerPort);

    while (network.getConnectedPeerCount() == 0) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));       // let the other side's Router see us too

    const std::string text = "hello from " + config.nodeName;
    router.broadcast(16, 1, std::vector<uint8_t>(text.begin(), text.end()));

    std::this_thread::sleep_for(std::chrono::seconds(10));
    router.stop();                                                      // before the Network it sits on
    network.stop();
}
