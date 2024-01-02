#include "File.h"

invilite::File::File(const std::string& filePath_, std::filesystem::perms filePermissions): filePath(filePath_), filePermissions(filePermissions) {}

bool invilite::File::read() {
    std::ios_base::openmode mode = std::ios::binary | std::ios::ate;
    std::ifstream infile(filePath, mode);
    if (!infile.is_open()) {
        return false;
    }

    std::streamsize size = infile.tellg();
    infile.seekg(0, std::ios::beg);

    content_.resize(size);
    if (!infile.read(reinterpret_cast<char*>(content_.data()), size)) {
        infile.close();
        return false;
    }

    infile.close();
    return true;
}

bool invilite::File::write() {
    // Create directory
    std::filesystem::path filePathObj(filePath);
    std::filesystem::create_directories(filePathObj.parent_path());

    std::ios_base::openmode mode = std::ios::binary;
    std::ofstream outfile(filePath, mode);
    if (!outfile.is_open()) {
        return false;
    }

    outfile.write(reinterpret_cast<const char*>(content_.data()), content_.size());
    outfile.close();

    std::filesystem::permissions(filePath, filePermissions);

    return true;
}

bool invilite::File::isExists() const {
    return std::filesystem::exists(filePath);
}

std::string invilite::File::getContentAsString() const {
    return std::string(content_.begin(), content_.end());
}

std::vector<uint8_t> invilite::File::getContentAsBytes() const {
    return content_;
}

size_t invilite::File::copyContentToByteArray(uint8_t* array, size_t size) const {
    size_t copySize = 0;
    if (array != nullptr && size > 0) {
        copySize = std::min(size, content_.size());
        std::copy(content_.begin(), content_.begin() + copySize, array);
    }

    return copySize;
}

void invilite::File::setContent(const std::vector<uint8_t>& data) {
    content_ = data;
}

void invilite::File::setContent(const std::string& content) {
    content_.assign(content.begin(), content.end());
}

void invilite::File::setContent(const uint8_t* data, size_t size) {
    content_.assign(data, data + size);
}
