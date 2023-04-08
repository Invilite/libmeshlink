#ifndef IP_TOOLS_H
#define IP_TOOLS_H

#include <vector>
#include <cstring>
#include <netdb.h>
#include <iostream>
#include <ifaddrs.h>
#include <arpa/inet.h>

namespace invilite {
	struct NetworkInterface {
		const std::string ifName;
		const std::string address;
		const std::string netmask;
		const std::string network;

		explicit NetworkInterface(std::string ifName, std::string address, std::string netmask, std::string network) : ifName(ifName), address(address), netmask(netmask), network(network) {}
	};

	class IpTools {
	public:
		static void getLocalInterfaces(std::vector<NetworkInterface> *interfacesList) {
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

		static bool isLocalAddress(std::vector<NetworkInterface> *interfacesList, std::string address) {
			for (const auto& entry: *interfacesList) {
		        if (entry.address == address) {
		        	return true;
		        }
		    }

		    return false;
		}

	};
}

#endif // IP_TOOLS_H