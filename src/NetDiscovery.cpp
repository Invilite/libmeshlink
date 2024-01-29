#include "NetDiscovery.h"

bool NetDiscovery::startListening() {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return false;
    }

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = port;
    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        std::cerr << "Bind error" << std::endl;
        return false;
    }

    isListening = true;
    listenerThread = std::thread(&NetDiscovery::listener, this);
    pthread_setname_np(listenerThread.native_handle(), "NetDiscovery");
    return true;
}

void NetDiscovery::stopListening() {
    if (isListening) {
        isListening = false;
        shutdown(sockfd, SHUT_RDWR);

        if(listenerThread.joinable()) {
            listenerThread.join();
        }

        close(sockfd);
        sockfd = -1;
    }
}

void NetDiscovery::discovery() {
    broadcast("meshlink:discovery");
}

void NetDiscovery::onDiscover(const std::function<void(const std::string&)> &callback) {
    discoverCallback = callback;
}

bool NetDiscovery::broadcast(const std::string &message) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return false;
    }

    int broadcastEnable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable)) < 0) {
        std::cerr << "Setsockopt error" << std::endl;
        close(sockfd);
        return false;
    }

    struct sockaddr_in broadcastAddr;
    bzero(&broadcastAddr, sizeof(broadcastAddr));
    broadcastAddr.sin_family = AF_INET;
    inet_pton(AF_INET, "255.255.255.255", &broadcastAddr.sin_addr);
    broadcastAddr.sin_port = port;

    ssize_t n = sendto(sockfd, message.c_str(), message.length(), 0, (struct sockaddr *)&broadcastAddr, sizeof(broadcastAddr));
    close(sockfd);
    return n >= 0;
}

void NetDiscovery::listener() {
    char buffer[MAXLINE];
    while (isListening) {
        struct sockaddr_in clientaddr;
        socklen_t len = sizeof(clientaddr);
        ssize_t n = recvfrom(sockfd, buffer, MAXLINE, 0, (struct sockaddr *)&clientaddr, &len);
        if (n < 0) {
            std::cerr << "Recvfrom error" << std::endl;
            continue;
        }
        buffer[n] = '\0';

        // Check if this message is discovery response
        const char* discovery_begin = "meshlink:discovery";
        if (strncmp(buffer, discovery_begin, strlen(discovery_begin)) == 0) {
            if (discoverCallback) {
                discoverCallback(inet_ntoa(clientaddr.sin_addr));
            }
        }
    }
}