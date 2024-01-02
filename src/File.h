#ifndef FILE_H
#define FILE_H

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <filesystem>

namespace invilite {

class File {
public:
    static constexpr auto public_perms = std::filesystem::perms::owner_read |
                                         std::filesystem::perms::owner_write |
                                         std::filesystem::perms::group_read |
                                         std::filesystem::perms::others_read;

    static constexpr auto private_perms = std::filesystem::perms::owner_read |
                                          std::filesystem::perms::owner_write;

    File(const std::string& filePath, std::filesystem::perms filePermissions = private_perms);
    bool read();
    bool write();
    bool isExists() const;
    std::string getContentAsString() const;
    std::vector<uint8_t> getContentAsBytes() const;
    size_t copyContentToByteArray(uint8_t* array, size_t size) const;
    void setContent(const std::vector<uint8_t>& data);
    void setContent(const std::string& content);
    void setContent(const uint8_t* data, size_t size);

    // Overloaded << operator for appending binary content
    File& operator<<(const std::vector<uint8_t>& data) {
        content_.insert(content_.end(), data.begin(), data.end());
        return *this;
    }

    // Overloaded << operator for appending string content, f.e.: file << "My string";
    File& operator<<(const std::string& str) {
        content_.insert(content_.end(), str.begin(), str.end());
        return *this;
    }

    // Overloaded << operator for appending content from a const uint8_t buffer, f.e.: myFile << std::make_pair(buffer, sizeof(buffer));
    File& operator<<(const std::pair<const uint8_t*, size_t>& buffer) {
        content_.insert(content_.end(), buffer.first, buffer.first + buffer.second);
        return *this;
    }

    // Overloaded >> operator for reading File content to std::string, f.e.: myFile >> buffer;
    friend std::string& operator>>(const File& file, std::string& str) {
        str = file.getContentAsString();
        return str;
    }

    // Overloaded >> operator for reading File content to std::vector<uint8_t>, f.e.: myFile >> buffer;
    friend std::vector<uint8_t>& operator>>(const File& file, std::vector<uint8_t>& buffer) {
        buffer = file.getContentAsBytes();
        return buffer;
    }

    // Overloaded >> operator for reading content into std::ostream, f.e.: std::cout >> myFile;
    friend std::ostream& operator>>(std::ostream& os, const File& file) {
        for (auto byte : file.getContentAsBytes()) {
            os << byte;
        }
        return os;
    }

    // Overloaded << operator for writing content from std::istream, f.e.: std::cin << myFile;
    friend std::istream& operator<<(std::istream& is, File& file) {
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
        file.setContent(data.data(), data.size());
        return is;
    }

protected:
    const std::string filePath;
    const std::filesystem::perms filePermissions;
    std::vector<uint8_t> content_;
};

} // namespace invilite

#endif // FILE_H
