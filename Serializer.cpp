#include "Serializer.h"

void invilite::Serializer::start_map(uint32_t header, size_t size) {
    stream_.write(reinterpret_cast<const char*>(&header), sizeof(header));
    stream_ << "{" << size << "}";
}

void invilite::Serializer::pack(const std::string& key, int value) {
    stream_ << "i" << key.size() << "|" << key << value << "|";
}

void invilite::Serializer::pack(const std::string& key, const std::string& value) {
    stream_ << "s" << key.size() << "|" << key << value.size() << "|" << value;
}

std::string invilite::Serializer::str() const {
    return stream_.str();
}

uint32_t invilite::Serializer::getHeader(const std::string& data) {
    uint32_t header;
    std::memcpy(&header, data.data(), sizeof(header));
    return header;
}

std::map<std::string, std::variant<int, std::string>> invilite::Serializer::unpack(const std::string& data) {
    std::istringstream stream(data);
    std::map<std::string, std::variant<int, std::string>> result;

    uint32_t header;
    stream.read(reinterpret_cast<char*>(&header), sizeof(header));

    char type;
    size_t key_size, value_size;
    std::string key;
    int int_value;
    std::string string_value;

    stream.ignore(1); // Ignore '{'
    size_t map_size;
    stream >> map_size;
    stream.ignore(1); // Ignore '}'

    for (size_t i = 0; i < map_size; i++) {
        stream >> type >> key_size;
        stream.ignore(1); // Ignore '|'
        key.resize(key_size);
        stream.read(&key[0], key_size);

        if (type == 'i') {
            stream >> int_value;
            stream.ignore(1); // Ignore '|'
            result[key] = int_value;
        } else if (type == 's') {
            stream >> value_size;
            stream.ignore(1); // Ignore '|'
            string_value.resize(value_size);
            stream.read(&string_value[0], value_size);
            result[key] = string_value;
        }
    }

    return result;
}
