#include <iostream>
#include <fstream>
#include <string>

namespace invilite {

class File {
public:
    File(const std::string& filePath_);
    bool read();
    bool write();
    const std::string& content() const;
    void content(const std::string& content);

    // Overloaded << operator for appending content
    File& operator<<(const std::string& str) {
        content_ += str;
        return *this;
    }

    // Overloaded >> operator for reading content from std::istream
    friend std::istream& operator>>(std::istream& is, File& file) {
        std::string line;
        while (std::getline(is, line)) {
            file.content_ += line + '\n';
        }
        return is;
    }

    // Overloaded << operator for writing content to std::ostream
    friend std::ostream& operator<<(std::ostream& os, const File& file) {
        os << file.content();
        return os;
    }

protected:
    const std::string filePath;
    std::string content_;
};

} // namespace invilite
