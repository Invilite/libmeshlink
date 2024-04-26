#include "MeshEvent.h"

uint64_t ntohll(uint64_t value) {
    // Sprawdzamy, czy system jest little-endian
    static const int num = 1;
    if (*(char *)&num == 1) {
        // System little-endian, więc trzeba zamienić kolejność bajtów
        const uint32_t high_part = ntohl(static_cast<uint32_t>(value >> 32));
        const uint32_t low_part = ntohl(static_cast<uint32_t>(value & 0xFFFFFFFFLL));

        return (static_cast<uint64_t>(low_part) << 32) | high_part;
    } else {
        // System big-endian, nie trzeba nic zmieniać
        return value;
    }
}

uint64_t htonll(uint64_t value) {
    // Sprawdzamy, czy system jest little-endian
    static const int num = 1;
    if (*(char *)&num == 1) {
        // System little-endian, więc trzeba zamienić kolejność bajtów
        const uint32_t high_part = htonl(static_cast<uint32_t>(value >> 32));
        const uint32_t low_part = htonl(static_cast<uint32_t>(value & 0xFFFFFFFFLL));

        return (static_cast<uint64_t>(low_part) << 32) | high_part;
    } else {
        // System big-endian, nie trzeba nic zmieniać
        return value;
    }
}

invilite::MeshEvent invilite::MeshEvent::deserialize(const std::vector<uint8_t>& data) {
    size_t index = 0;

    // Odczytaj 'type' i 'reserved' bezpośrednio, nie wymagają konwersji
    uint8_t type = data[index++];
    uint8_t reserved = data[index++];

    // Konwersja i odczyt 'ttl' z big-endian
    uint16_t ttl_network;
    std::memcpy(&ttl_network, &data[index], sizeof(ttl_network));
    index += sizeof(ttl_network);

    MeshEvent event(type, ntohs(ttl_network));
    event.reserved = reserved;

    // Konwersja i odczyt 'created' z big-endian
    uint64_t created_network;
    std::memcpy(&created_network, &data[index], sizeof(created_network));
    event.created = ntohll(created_network);
    index += sizeof(created_network);

    // Odczytaj 'uuid', bez konwersji
    std::array<uint8_t, 16> uuid;
    std::memcpy(uuid.data(), &data[index], uuid.size());
    event.uuid = uuid;
    index += uuid.size();

    // Odczytaj rozmiar i zawartość 'topic'
    uint16_t topic_size_network;
    std::memcpy(&topic_size_network, &data[index], sizeof(topic_size_network));
    uint16_t topic_size = ntohs(topic_size_network);
    index += sizeof(topic_size_network);
    std::vector<uint8_t> topic(data.begin() + index, data.begin() + index + topic_size);
    event.setTopic(&topic);
    index += topic_size;

    // Odczytaj rozmiar i zawartość 'data'
    uint32_t data_size_network;
    std::memcpy(&data_size_network, &data[index], sizeof(data_size_network));
    uint32_t data_size = ntohl(data_size_network);
    index += sizeof(data_size_network);
    std::vector<uint8_t> data_content(data.begin() + index, data.begin() + index + data_size);
    event.setData(&data_content);

    return event;
}

invilite::MeshEvent::MeshEvent(uint8_t type, uint16_t ttl): type(type), ttl(ttl) {
	// Save time of creation for this event
	auto now = std::chrono::system_clock::now();
	auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    this->created = seconds.count();

	// Generale UUID of this event
	uuid_t _uuid;
	//uuid_generate_time(_uuid);
    uuid_generate_random(_uuid);
    std::memcpy(this->uuid.data(), _uuid, 16);

    // Reserved is not used and set to zero
    this->reserved = 0;
}

std::vector<uint8_t> invilite::MeshEvent::serialize() const {
	std::vector<uint8_t> serialized;

    // Dodaj 'type' i 'reserved' bezpośrednio, nie wymagają konwersji
    serialized.push_back(this->type);
    serialized.push_back(this->reserved);

    // Konwersja i dodanie 'ttl' (big-endian)
    uint16_t ttl_network = htons(this->ttl);
    serialized.insert(serialized.end(), reinterpret_cast<uint8_t*>(&ttl_network), reinterpret_cast<uint8_t*>(&ttl_network) + sizeof(ttl_network));

    // Konwersja i dodanie 'created' (big-endian)
    uint64_t created_network = htonll(this->created);
    serialized.insert(serialized.end(), reinterpret_cast<uint8_t*>(&created_network), reinterpret_cast<uint8_t*>(&created_network) + sizeof(created_network));

    // Dodaj 'uuid', bez konwersji
    serialized.insert(serialized.end(), this->uuid.begin(), this->uuid.end());

    // Dodaj rozmiar i zawartość 'topic'
    uint16_t topic_size_network = htons(static_cast<uint16_t>(this->getTopic().size()));
    serialized.insert(serialized.end(), reinterpret_cast<uint8_t*>(&topic_size_network), reinterpret_cast<uint8_t*>(&topic_size_network) + sizeof(topic_size_network));
    serialized.insert(serialized.end(), this->getTopic().begin(), this->getTopic().end());

    // Dodaj rozmiar i zawartość 'data'
    uint32_t data_size_network = htonl(static_cast<uint32_t>(this->getData().size()));
    serialized.insert(serialized.end(), reinterpret_cast<uint8_t*>(&data_size_network), reinterpret_cast<uint8_t*>(&data_size_network) + sizeof(data_size_network));
    serialized.insert(serialized.end(), this->getData().begin(), this->getData().end());

    return serialized;
}

uint8_t invilite::MeshEvent::getType() {
	return this->type;
}

uint16_t invilite::MeshEvent::getTtl() {
	return this->ttl;
}

uint64_t invilite::MeshEvent::getCreated() {
	return this->created;
}

std::array<uint8_t, 16> invilite::MeshEvent::getId() {
	return this->uuid;
}

const std::vector<uint8_t>& invilite::MeshEvent::getTopic() const {
	return this->topic;
}

const std::vector<uint8_t>& invilite::MeshEvent::getData() const {
	return this->data;
}

void invilite::MeshEvent::setTopic(const std::vector<uint8_t>* topic) {
	if (topic != nullptr) {
        this->topic = *topic; // Kopiowanie danych z wektora wskazywanego przez topic do pola klasy
    } else {
        this->topic.clear(); // Jeśli wskaźnik jest nullptr, czyścimy istniejący temat
    }
}

void invilite::MeshEvent::setData(const std::vector<uint8_t>* data) {
	if (data != nullptr) {
        this->data = *data; // Kopiowanie danych z wektora wskazywanego przez data do pola klasy
    } else {
        this->data.clear(); // Jeśli wskaźnik jest nullptr, czyścimy istniejące dane
    }
}

void invilite::MeshEvent::setTopic(const char* topic) {
	if (topic != nullptr) {
        this->topic.clear(); // Wyczyść obecny temat
        while (*topic != '\0') { // Przechodzimy przez ciąg znaków do końca
            this->topic.push_back(static_cast<uint8_t>(*topic)); // Konwersja każdego znaku na uint8_t i dodanie do wektora
            ++topic;
        }
    } else {
        this->topic.clear(); // Jeśli wskaźnik jest nullptr, czyścimy istniejący temat
    }
}

void invilite::MeshEvent::setData(const char* data) {
	if (data != nullptr) {
        this->data.clear(); // Wyczyść obecne dane
        while (*data != '\0') { // Przechodzimy przez ciąg znaków do końca
            this->data.push_back(static_cast<uint8_t>(*data)); // Konwersja każdego znaku na uint8_t i dodanie do wektora
            ++data;
        }
    } else {
        this->data.clear(); // Jeśli wskaźnik jest nullptr, czyścimy istniejące dane
    }
}
