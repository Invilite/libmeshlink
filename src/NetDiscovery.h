#ifndef NET_DISCOVERY_H
#define NET_DISCOVERY_H

#include <atomic>
#include <thread>
#include <cstring>
#include <unistd.h>
#include <iostream>
#include <functional>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MAXLINE 1024

class NetDiscovery {
public:
    NetDiscovery(const int port): port(port), sockfd(-1), isListening(false) {}
    bool startListening();
    void stopListening();
    void discovery();
    void onDiscover(const std::function<void(const std::string&)> &callback);

private:
    bool broadcast(const std::string &message);
    void listener();

    const int port;
    int sockfd;
    std::atomic<bool> isListening;
    std::function<void(const std::string&)> discoverCallback;
    std::thread listenerThread;
};

#endif // NET_DISCOVERY_H