#ifndef MESH_EVENT_H
#define MESH_EVENT_H

#include <array>
#include <chrono>
#include <vector>
#include <cstdint>
#include <cstring>
#include <uuid/uuid.h>
#include <arpa/inet.h>
#include <netinet/in.h>

namespace invilite {
	class MeshEvent {
	public:
		MeshEvent(uint8_t type = 0, uint16_t ttl = INT16_MAX);
		static MeshEvent deserialize(const std::vector<uint8_t>& data);
		std::vector<uint8_t> serialize() const;

		uint8_t  getType();
		uint16_t getTtl();
		uint64_t getCreated();
		std::array<uint8_t, 16> getId();
		const std::vector<uint8_t>& getTopic() const;
		const std::vector<uint8_t>& getData() const;

		void setTopic(const std::vector<uint8_t>* topic);
		void setTopic(const char* topic);
		void setData(const std::vector<uint8_t>* data);
		void setData(const char* data, size_t size);

	protected:
		const uint8_t type;
		uint8_t  reserved;
		uint16_t ttl;
		uint64_t created;
		std::array<uint8_t, 16> uuid;
		std::vector<uint8_t> topic;
		std::vector<uint8_t> data;

	private:
	};
}

#endif
