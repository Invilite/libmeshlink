#ifndef CLIENT_ID_H
#define CLIENT_ID_H

#include <ctime>
#include <random>
#include <string>
#include <cstring>
#include <sstream>
#include <fstream>
#include <iostream>

#include "File.h"

namespace invilite {

class ClientId : public File {
public:
    ClientId(const std::string& filePath);
    std::string getId() const;

protected:
    std::string generateId();
    std::string getRandomString(size_t length);
    std::string getHardwareUniqueId();
    std::string getTimePart();

private:
    std::string id_;
};

} // namespace invilite

#endif
