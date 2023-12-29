#include "ClientId.h"

invilite::ClientId::ClientId(const std::string& filePath): File(filePath) {
    if (!read()) {
        id_ = generateId();
        content(id_);
        write();
    } else {
        id_ = content();
    }
}

std::string invilite::ClientId::getId() const {
    return id_;
}

std::string invilite::ClientId::getRandomString(size_t length) {
    static const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, chars.size() - 1);

    std::string random_string;
    random_string.reserve(length);

    for (size_t i = 0; i < length; ++i) {
        random_string.push_back(chars[distrib(gen)]);
    }

    return random_string;
}

std::string invilite::ClientId::getHardwareUniqueId() {
    return getRandomString(6) + "-" + getRandomString(8);
}

std::string invilite::ClientId::generateId() {
    std::string hardwareId = getHardwareUniqueId();
    std::string random_part = getRandomString(6);
    std::string time_part = getTimePart();

    return hardwareId + "-" + random_part + "-" + time_part;
}

std::string invilite::ClientId::getTimePart() {
    std::time_t now = std::time(nullptr);
    std::stringstream ss;
    ss << std::hex << now;

    return ss.str();
}
