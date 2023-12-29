#include "IpTools.h"

void invilite::IpTools::getLocalInterfaces(std::vector<NetworkInterface> *interfacesList) {
	struct ifaddrs* ifaddr = nullptr;
    struct ifaddrs* ifa = nullptr;
    int status;
    char host[NI_MAXHOST];
    char netmask[NI_MAXHOST];
    char network[INET_ADDRSTRLEN];

    status = getifaddrs(&ifaddr);
    if (status == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    // Przejście przez listę interfejsów sieciowych
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        int family = ifa->ifa_addr->sa_family;

        // Wyświetlanie informacji tylko dla interfejsów IPv4
        if (family == AF_INET) {
            status = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                 host, NI_MAXHOST,
                                 nullptr, 0, NI_NUMERICHOST);

            if (status != 0) {
                std::cout << "getnameinfo() failed: " << gai_strerror(status) << std::endl;
                continue;
            }

            // Pobranie maski podsieci
            getnameinfo(ifa->ifa_netmask, sizeof(struct sockaddr_in),
                        netmask, NI_MAXHOST,
                        nullptr, 0, NI_NUMERICHOST);

            // Obliczenie adresu sieci
            struct sockaddr_in addr, mask, net;
            memcpy(&addr, ifa->ifa_addr, sizeof(struct sockaddr_in));
            memcpy(&mask, ifa->ifa_netmask, sizeof(struct sockaddr_in));
            net.sin_addr.s_addr = addr.sin_addr.s_addr & mask.sin_addr.s_addr;
            inet_ntop(AF_INET, &(net.sin_addr), network, INET_ADDRSTRLEN);

            NetworkInterface networkInterface(std::string(ifa->ifa_name), std::string(host), std::string(netmask), std::string(network));
            interfacesList->push_back(networkInterface);

            //std::cout << "Interface: " << ifa->ifa_name << ", Address: " << host << ", Netmask: " << netmask << ", Network: " << network << std::endl;
        }
    }

    // Zwolnienie zaalokowanej listy interfejsów sieciowych
    freeifaddrs(ifaddr);
}

bool invilite::IpTools::isLocalAddress(std::vector<NetworkInterface> *interfacesList, std::string address) {
	for (const auto& entry: *interfacesList) {
        if (entry.address == address) {
        	return true;
        }
    }

    return false;
}

std::vector<std::string> invilite::IpTools::split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

bool invilite::IpTools::isLocalNetworkAddress(const std::string& address) {
    std::vector<std::string> octets = split(address, '.');

    if (octets.size() != 4) {
        return false;
    }

    int firstOctet = std::stoi(octets[0]);

    if (firstOctet == 10) {
        return true;
    }

    if (firstOctet == 172 && std::stoi(octets[1]) >= 16 && std::stoi(octets[1]) <= 31) {
        return true;
    }

    if (firstOctet == 192 && std::stoi(octets[1]) == 168) {
        return true;
    }

    return false;
}

double invilite::IpTools::ping(const std::string &address, int packets, int wait_time, int interval) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        std::cerr << "Nie można utworzyć gniazda. Upewnij się, że masz uprawnienia administratora." << std::endl;
        return -1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = inet_addr(address.c_str());

    struct icmphdr icmp_hdr;
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.un.echo.id = getpid();

    unsigned char data[56] = {0};
    memcpy(data, &icmp_hdr, sizeof(icmp_hdr));

    icmp_hdr.checksum = checksum((unsigned short *)data, sizeof(data));

    int receivedPackets = 0;
    double responseTimeSum = 0;

    for (int i = 0; i < packets; ++i) {
        auto start = std::chrono::steady_clock::now();
        if (sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            std::cerr << "Wysyłanie nie powiodło się" << std::endl;
            return -2;
        }

        char recv_buf[64] = {0};
        struct sockaddr_in r_addr;
        socklen_t r_addr_len = sizeof(r_addr);

        struct timeval tv;
        tv.tv_sec = wait_time / 1000;
        tv.tv_usec = (wait_time % 1000) * 1000;

        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int recv_bytes = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&r_addr, &r_addr_len);

        if (recv_bytes < 0) {
            std::cerr << "Nie otrzymano odpowiedzi" << std::endl;
        } else {
            auto end = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            responseTimeSum += duration;
            receivedPackets++;
            std::cout << "Odpowiedź z " << address << ": seq=" << i << " czas=" << duration << "ms" << std::endl;
        }

        if (i < packets - 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
        }
    }

    close(sockfd);

    if (receivedPackets > 0) {
        return responseTimeSum / receivedPackets;
    }

    return -3;
}

unsigned short invilite::IpTools::checksum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return answer;
}
