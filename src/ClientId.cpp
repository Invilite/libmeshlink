#include "ClientId.h"

invilite::ClientId::ClientId(const std::string& filePath): File(filePath, public_perms) {
    if (!read()) {
        generateId();
        this->setContent(id, sizeof(id));
        write();
    } else {
        this->copyContentToByteArray(id, sizeof(id));
    }
}

std::string invilite::ClientId::getIdAsString() const {
    std::stringstream ss;
    for (int i = 0; i < 16; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(id[i]);
        if (i == 3 || i == 7 || i == 11) {
            ss << "-";
        }
    }
    return ss.str();
}

void invilite::ClientId::getRandomBytes(uint8_t* output, size_t length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> distrib(0, 255);

    for (size_t i = 0; i < length; ++i) {
        output[i] = distrib(gen);
    }
}

void invilite::ClientId::getHardwareId(uint8_t* output, size_t length) {
    std::string hardwareId;

    // Prepare generator of random data
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);

    // Try to read machine id
    std::ifstream file("/etc/machine-id");
    std::stringstream buffer;
    if (file) {
        buffer << file.rdbuf();
        file.close();
        hardwareId = buffer.str();
    }

    if (hardwareId.empty()) {
        // Get CPU id
        std::array<uint32_t, 4> cpuId = {0};
        if (!this->getCpuId(cpuId)) {
            // Fallback for random data
            for (uint32_t &val : cpuId) {
                val = dist(gen);
            }
        }

        // Get host id
        long hostId = gethostid();

        // Combine cpuId with hostId
        std::stringstream ss;
        for (uint32_t val : cpuId) {
            ss << std::hex << std::setw(8) << std::setfill('0') << val;
        }
        ss << std::hex << std::setw(8) << std::setfill('0') << hostId;

        hardwareId = ss.str();
    }

    CryptoPP::SHA1 sha1;
    CryptoPP::byte digest[CryptoPP::SHA1::DIGESTSIZE];
    sha1.CalculateDigest(digest, reinterpret_cast<const CryptoPP::byte*>(hardwareId.data()), hardwareId.size());
    size_t bytesToCopy = std::min(length, sizeof(digest));
    std::memcpy(output, digest, bytesToCopy);
}

void invilite::ClientId::generateId() {
    this->getHardwareId(id, 8);
    this->getRandomBytes(id + 8, 4);
    this->getTimeBytes(id + 12, 4);
}

void invilite::ClientId::getTimeBytes(uint8_t* output, size_t length) {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

    // Kopiujemy bajty z millis do output, ale nie więcej niż length bajtów
    size_t bytesToCopy = std::min(length, sizeof(millis));
    std::memcpy(output, &millis, bytesToCopy);
}

bool invilite::ClientId::getCpuId(std::array<uint32_t, 4>& cpu_id) {
    return __get_cpuid(0, &cpu_id[0], &cpu_id[1], &cpu_id[2], &cpu_id[3]);
}
