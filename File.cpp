#include "File.h"


invilite::File::File(const std::string& filePath_) : filePath(filePath_) {
    
}

bool invilite::File::read() {
    std::ifstream infile(filePath);
    if (!infile.is_open()) {
        return false;
    }

    content_ = std::string((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
    infile.close();
    return true;
}

bool invilite::File::write() {
    std::ofstream outfile(filePath);
    if (!outfile.is_open()) {
        return false;
    }

    outfile << content_;
    outfile.close();
    return true;
}

const std::string& invilite::File::content() const {
    return content_;
}

void invilite::File::content(const std::string& content) {
    content_ = content;
}


// int main() {
//     invilite::File file("example.txt");

//     // Write content to the file
//     file.set_content("Hello, world!");
//     if (file.write()) {
//         std::cout << "File written successfully." << std::endl;
//     } else {
//         std::cout << "Failed to write the file." << std::endl;
//     }

//     // Read content from the file
//     if (file.read()) {
//         std::cout << "File read successfully." << std::endl;
//         std::cout << "Content: " << file.content() << std::endl;
//     } else {
//         std::cout << "Failed to read the file." << std::endl;
//     }

//     return 0;
// }