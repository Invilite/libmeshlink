#include "meshlink/log.h"

#include <iostream>

namespace invilite::Mesh {

std::string_view logLevelName(LogLevel level) {
    switch (level) {
        case LogLevel::Emergency: return "emerg";
        case LogLevel::Alert:     return "alert";
        case LogLevel::Critical:  return "crit";
        case LogLevel::Error:     return "err";
        case LogLevel::Warning:   return "warning";
        case LogLevel::Notice:    return "notice";
        case LogLevel::Info:      return "info";
        case LogLevel::Debug:     return "debug";
    }
    return "unknown";
}

void StderrLogSink::write(const LogRecord& record) {
    // Build the whole line first, so concurrent writers never interleave inside a line
    const std::string line = std::format("<{}>{}: {}\n", static_cast<int>(record.level), record.component, record.text);
    std::lock_guard lock(this->writeMutex);
    std::cerr << line << std::flush;
}

Logger::Logger(std::shared_ptr<LogSink> sink, LogLevel threshold, bool debugDetailsEnabled)
    : sink(sink ? std::move(sink) : std::make_shared<StderrLogSink>()), threshold(static_cast<uint8_t>(threshold)), debugDetailsEnabled(debugDetailsEnabled) {}

void Logger::write(LogLevel level, std::string_view component, std::string_view text, bool isDebug) const {
    if (!this->isEnabled(level, isDebug)) return;
    try {
        this->sink->write(LogRecord{level, isDebug, component, text});
    } catch (...) {
        // Nowhere left to report it; a failing sink must not kill the I/O, management or Router thread
    }
}

ComponentLog::ComponentLog(std::shared_ptr<Logger> logger, std::string_view component)
    : logger(logger ? std::move(logger) : std::make_shared<Logger>()), component(component) {}

LogRateLimiter::LogRateLimiter(Clock::duration window, size_t maxKeys) : window(window), maxKeys(maxKeys) {}

std::optional<uint32_t> LogRateLimiter::admit(std::string_view key, Clock::time_point now) {
    auto it = this->states.find(std::string(key));
    if (it == this->states.end()) {
        if (this->states.size() >= this->maxKeys) this->forgetLeastRecentlySeenKey();
        this->states.emplace(std::string(key), KeyState{now, now, 0});
        return 0u;
    }

    KeyState& state = it->second;
    state.lastSeen = now;
    if (now - state.windowStart < this->window) {
        ++state.suppressed;
        return std::nullopt;
    }
    const uint32_t suppressed = state.suppressed;
    state.windowStart = now;
    state.suppressed  = 0;
    return suppressed;
}

std::string LogRateLimiter::suppressedNote(uint32_t suppressed) {
    return suppressed == 0 ? std::string() : std::format(" ({} similar suppressed)", suppressed);
}

void LogRateLimiter::forgetLeastRecentlySeenKey() {
    // Linear scan: the cap is small (256) and this runs only when a new key arrives at the cap
    auto oldest = this->states.begin();
    for (auto it = this->states.begin(); it != this->states.end(); ++it) {
        if (it->second.lastSeen < oldest->second.lastSeen) oldest = it;
    }
    if (oldest != this->states.end()) this->states.erase(oldest);
}

} // namespace invilite::Mesh
