#ifndef IP_TOOLS_H
#define IP_TOOLS_H

#include <vector>
#include <string>
#include <thread>
#include <cstring>
#include <sstream>
#include <netdb.h>
#include <unistd.h>
#include <iostream>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

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
		static void getLocalInterfaces(std::vector<NetworkInterface> *interfacesList);
		static bool isLocalAddress(std::vector<NetworkInterface> *interfacesList, std::string address);
		static bool isLocalNetworkAddress(const std::string& address);
		static double ping(const std::string &address, int packets = 4, int wait_time = 1000, int interval = 200);

	private:
		static std::vector<std::string> split(const std::string& s, char delimiter);
		static unsigned short checksum(unsigned short *ptr, int nbytes);

	};
}

#endif // IP_TOOLS_H