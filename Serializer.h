#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <map>
#include <vector>
#include <string>
#include <cstring>
#include <variant>
#include <sstream>
#include <iostream>

namespace invilite {

    class Serializer {
    public:
        void start_map(uint32_t header, size_t size);
        void pack(const std::string& key, int value);
        void pack(const std::string& key, const std::string& value);
        std::string str() const;
        static uint32_t getHeader(const std::string& data);
        static std::map<std::string, std::variant<int, std::string>> unpack(const std::string& data);

    private:
        std::ostringstream stream_;
    };
}

#endif // SERIALIZER_H
