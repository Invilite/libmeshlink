#ifndef NODE_ID_H
#define NODE_ID_H

#include <ctime>
#include <array>
#include <cctype>
#include <random>
#include <string>
#include <iomanip>
#include <cpuid.h>
#include <cstring>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <iostream>
#include <crypto++/sha.h>
#include <crypto++/hex.h>

#include "File.h"

namespace invilite {

class NodeId : public File {
public:
    NodeId(const std::string& filePath);
    std::string getIdAsString() const;

protected:
    void generateId();
    void getRandomBytes(uint8_t* output, size_t length);
    void getHardwareId(uint8_t* output, size_t length);
    void getTimeBytes(uint8_t* output, size_t length);

private:
    uint8_t id[16];
    std::string id_;
    bool getCpuId(std::array<uint32_t, 4>& cpu_id);
};

} // namespace invilite

#endif
