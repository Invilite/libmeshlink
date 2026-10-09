#pragma once

#ifndef MESH_LOG_H
#define MESH_LOG_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace invilite::Mesh {

    // Severity with syslog numbering. The library never emits Emergency: only the application knows whether it stopped
    // working altogether.
    enum class LogLevel : uint8_t { Emergency = 0, Alert, Critical, Error, Warning, Notice, Info, Debug };

    // syslog keyword of the level: "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"
    std::string_view logLevelName(LogLevel level);

    // One log entry handed to a sink. isDebug marks noisy debugging detail (addresses, frame contents, every frame):
    // such records pass the filter only with the Debug threshold AND debug details enabled (-v together with --debug).
    // The views are valid only for the duration of LogSink::write.
    struct LogRecord {
        LogLevel         level;
        bool             isDebug;
        std::string_view component;                                                     // "Network", "Router"
        std::string_view text;
    };

    // Receives records that passed the Logger's filter. Called concurrently from several library threads, so an
    // implementation must be thread-safe; it should not block for long (the I/O and Router threads call it).
    class LogSink {
    public:
        virtual ~LogSink() = default;
        virtual void write(const LogRecord& record) = 0;
    };

    // Default sink: "<N>Component: text" on std::cerr, one line per record. <N> is the syslog priority in the sd-daemon
    // format, so journald assigns the right priority when stderr goes to the journal.
    class StderrLogSink : public LogSink {
    public:
        void write(const LogRecord& record) override;
    private:
        std::mutex writeMutex;
    };

    // Filter in front of a sink: a severity threshold plus the debug-details switch. Thread-safe; both settings may be
    // changed while library threads log. One Logger is normally shared by Network and Router.
    class Logger {
    public:
        explicit Logger(std::shared_ptr<LogSink> sink = std::make_shared<StderrLogSink>(), LogLevel threshold = LogLevel::Info, bool debugDetailsEnabled = false);

        [[nodiscard]] bool isEnabled(LogLevel level, bool isDebug = false) const {
            return static_cast<uint8_t>(level) <= this->threshold.load(std::memory_order_relaxed) && (!isDebug || this->debugDetailsEnabled.load(std::memory_order_relaxed));
        }

        // Writes when the filter passes. An exception thrown by the sink is swallowed: logging must never take down
        // the thread that logs.
        void write(LogLevel level, std::string_view component, std::string_view text, bool isDebug = false) const;

        void setThreshold(LogLevel level) { this->threshold.store(static_cast<uint8_t>(level), std::memory_order_relaxed); }
        void setDebugDetailsEnabled(bool enabled) { this->debugDetailsEnabled.store(enabled, std::memory_order_relaxed); }

    private:
        std::shared_ptr<LogSink> sink;
        std::atomic<uint8_t>     threshold;
        std::atomic<bool>        debugDetailsEnabled;
    };

    // Bounds messages a remote peer can trigger (malformed frames, protocol violations), so a misbehaving neighbor
    // cannot flood the log. Per key (event kind + neighbor), the first record in each window passes and the rest are
    // counted; the next record let through reports how many were suppressed. The key count is bounded too (at the cap
    // the least recently seen key is forgotten), so the limiter itself cannot be used to exhaust memory.
    // Not thread-safe: each logging thread owns its own limiter. Time is passed in, so tests need no sleeping.
    class LogRateLimiter {
    public:
        using Clock = std::chrono::steady_clock;

        explicit LogRateLimiter(Clock::duration window = std::chrono::seconds(10), size_t maxKeys = 256);

        // nullopt = suppress this record; otherwise log it, the value being the number suppressed since the last one let through
        [[nodiscard]] std::optional<uint32_t> admit(std::string_view key, Clock::time_point now);

        // Suffix for a record let through: "" or " (N similar suppressed)"
        [[nodiscard]] static std::string suppressedNote(uint32_t suppressed);

    private:
        struct KeyState {
            Clock::time_point windowStart;
            Clock::time_point lastSeen;
            uint32_t          suppressed = 0;
        };

        void forgetLeastRecentlySeenKey();

        Clock::duration                           window;
        size_t                                    maxKeys;
        std::unordered_map<std::string, KeyState> states;
    };

    // A Logger bound to one component name, as held by Network and Router. Formatting happens only after the filter
    // passed, so a disabled message costs two atomic loads.
    class ComponentLog {
    public:
        ComponentLog(std::shared_ptr<Logger> logger, std::string_view component);       // a null logger gives the default Logger (stderr, Info)

        [[nodiscard]] bool isEnabled(LogLevel level, bool isDebug = false) const { return this->logger->isEnabled(level, isDebug); }

        template <class... Args>
        void format(LogLevel level, std::format_string<Args...> fmt, Args&&... args) const {
            if (!this->logger->isEnabled(level)) return;
            this->logger->write(level, this->component, std::format(fmt, std::forward<Args>(args)...));
        }

        // Debug record with isDebug set: noisy details shown only with -v and --debug together
        template <class... Args>
        void formatDebugDetail(std::format_string<Args...> fmt, Args&&... args) const {
            if (!this->logger->isEnabled(LogLevel::Debug, true)) return;
            this->logger->write(LogLevel::Debug, this->component, std::format(fmt, std::forward<Args>(args)...), true);
        }

        // For messages a remote peer can trigger: at most one per window per key (event kind + peer); the record let
        // through after suppression reports how many were dropped. `limiter` must belong to the calling thread.
        template <class... Args>
        void formatRateLimited(LogRateLimiter& limiter, std::string_view key, LogLevel level, std::format_string<Args...> fmt, Args&&... args) const {
            if (!this->logger->isEnabled(level)) return;                                // a filtered record must not use up the window
            const std::optional<uint32_t> suppressed = limiter.admit(key, LogRateLimiter::Clock::now());
            if (!suppressed) return;
            this->logger->write(level, this->component, std::format(fmt, std::forward<Args>(args)...) + LogRateLimiter::suppressedNote(*suppressed));
        }

        [[nodiscard]] const std::shared_ptr<Logger>& getLogger() const { return this->logger; }

    private:
        std::shared_ptr<Logger> logger;
        std::string_view        component;                                              // always a string literal
    };

} // namespace invilite::Mesh

#endif // MESH_LOG_H
