#pragma once

// Test sink that keeps every record it receives, so tests can assert on levels and texts.
#include "meshlink/log.h"

#include <algorithm>
#include <mutex>
#include <string>
#include <vector>

namespace invilite::Mesh::TestHelpers {

struct CollectedRecord { LogLevel level; bool isDebug; std::string component; std::string text; };

class CollectingLogSink : public LogSink {
public:
    void write(const LogRecord& record) override {
        std::lock_guard lock(this->mutex);
        this->records.push_back({record.level, record.isDebug, std::string(record.component), std::string(record.text)});
    }

    std::vector<CollectedRecord> snapshot() { std::lock_guard lock(this->mutex); return this->records; }

    size_t countContaining(LogLevel level, const std::string& fragment) {
        std::lock_guard lock(this->mutex);
        return static_cast<size_t>(std::count_if(this->records.begin(), this->records.end(), [&](const CollectedRecord& r) { return r.level == level && r.text.find(fragment) != std::string::npos; }));
    }

    size_t countAtLevel(LogLevel level) {
        std::lock_guard lock(this->mutex);
        return static_cast<size_t>(std::count_if(this->records.begin(), this->records.end(), [&](const CollectedRecord& r) { return r.level == level; }));
    }

private:
    std::mutex                   mutex;
    std::vector<CollectedRecord> records;
};

} // namespace invilite::Mesh::TestHelpers
