#include <gtest/gtest.h>
#include "meshlink/log.h"

#include <mutex>
#include <sstream>
#include <stdexcept>
#include <vector>

using namespace invilite::Mesh;
using namespace std::chrono_literals;

namespace {

struct CollectedRecord { LogLevel level; bool isDebug; std::string component; std::string text; };

class CollectingLogSink : public LogSink {
public:
    void write(const LogRecord& record) override {
        std::lock_guard lock(this->mutex);
        this->records.push_back({record.level, record.isDebug, std::string(record.component), std::string(record.text)});
    }
    std::vector<CollectedRecord> snapshot() { std::lock_guard lock(this->mutex); return this->records; }
private:
    std::mutex                   mutex;
    std::vector<CollectedRecord> records;
};

class ThrowingLogSink : public LogSink {
public:
    void write(const LogRecord&) override { throw std::runtime_error("sink failed"); }
};

// Counts how many times it was formatted — proves that a filtered-out message is never formatted
struct FormatCounter { int* formatted; };

const auto T0 = std::chrono::steady_clock::time_point(std::chrono::seconds(1000));

} // namespace

template <>
struct std::formatter<FormatCounter> : std::formatter<std::string_view> {
    auto format(const FormatCounter& counter, std::format_context& context) const {
        ++*counter.formatted;
        return std::formatter<std::string_view>::format("counted", context);
    }
};

TEST(LoggerTest, ThresholdFiltersLowerLevels) {
    auto sink = std::make_shared<CollectingLogSink>();
    Logger logger(sink, LogLevel::Info);

    EXPECT_TRUE(logger.isEnabled(LogLevel::Notice));
    EXPECT_TRUE(logger.isEnabled(LogLevel::Info));
    EXPECT_FALSE(logger.isEnabled(LogLevel::Debug));

    logger.write(LogLevel::Debug, "Network", "hidden");
    logger.write(LogLevel::Warning, "Network", "shown");
    const auto records = sink->snapshot();
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(records[0].level, LogLevel::Warning);
    EXPECT_EQ(records[0].component, "Network");
    EXPECT_EQ(records[0].text, "shown");
}

TEST(LoggerTest, DebugDetailsNeedBothSwitches) {
    auto sink = std::make_shared<CollectingLogSink>();
    EXPECT_FALSE(Logger(sink, LogLevel::Info, true).isEnabled(LogLevel::Debug, true));      // --debug without -v
    EXPECT_FALSE(Logger(sink, LogLevel::Debug, false).isEnabled(LogLevel::Debug, true));    // -v without --debug
    EXPECT_TRUE(Logger(sink, LogLevel::Debug, true).isEnabled(LogLevel::Debug, true));
    EXPECT_TRUE(Logger(sink, LogLevel::Debug, false).isEnabled(LogLevel::Debug, false));
}

TEST(LoggerTest, ComponentLogFormatsOnlyWhenEnabled) {
    auto sink   = std::make_shared<CollectingLogSink>();
    auto logger = std::make_shared<Logger>(sink, LogLevel::Info);
    ComponentLog log(logger, "Router");
    int formatted = 0;

    log.format(LogLevel::Debug, "value {}", FormatCounter{&formatted});
    log.formatDebugDetail("value {}", FormatCounter{&formatted});
    EXPECT_EQ(formatted, 0);
    EXPECT_TRUE(sink->snapshot().empty());

    log.format(LogLevel::Notice, "value {}", FormatCounter{&formatted});
    EXPECT_EQ(formatted, 1);
    const auto records = sink->snapshot();
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(records[0].component, "Router");
    EXPECT_EQ(records[0].text, "value counted");
    EXPECT_FALSE(records[0].isDebug);
}

TEST(LoggerTest, DebugDetailRecordsAreMarked) {
    auto sink = std::make_shared<CollectingLogSink>();
    ComponentLog log(std::make_shared<Logger>(sink, LogLevel::Debug, true), "Network");
    log.formatDebugDetail("frame {} B", 42);
    const auto records = sink->snapshot();
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(records[0].level, LogLevel::Debug);
    EXPECT_TRUE(records[0].isDebug);
    EXPECT_EQ(records[0].text, "frame 42 B");
}

TEST(LoggerTest, ThresholdChangesAtRuntime) {
    auto sink = std::make_shared<CollectingLogSink>();
    Logger logger(sink, LogLevel::Info);
    logger.setThreshold(LogLevel::Debug);
    logger.setDebugDetailsEnabled(true);
    EXPECT_TRUE(logger.isEnabled(LogLevel::Debug, true));
    logger.setThreshold(LogLevel::Error);
    EXPECT_FALSE(logger.isEnabled(LogLevel::Warning));
    EXPECT_TRUE(logger.isEnabled(LogLevel::Alert));
}

TEST(LoggerTest, ThrowingSinkDoesNotPropagate) {
    Logger logger(std::make_shared<ThrowingLogSink>(), LogLevel::Info);
    EXPECT_NO_THROW(logger.write(LogLevel::Error, "Network", "x"));
}

TEST(LoggerTest, ComponentLogWithoutLoggerUsesDefault) {
    ComponentLog log(nullptr, "Network");
    ASSERT_NE(log.getLogger(), nullptr);
    EXPECT_TRUE(log.isEnabled(LogLevel::Info));
    EXPECT_FALSE(log.isEnabled(LogLevel::Debug));
}

TEST(LoggerTest, StderrSinkWritesSyslogPrefix) {
    std::stringstream captured;
    auto* previous = std::cerr.rdbuf(captured.rdbuf());
    StderrLogSink().write(LogRecord{LogLevel::Warning, false, "Network", "x"});
    std::cerr.rdbuf(previous);
    EXPECT_EQ(captured.str(), "<4>Network: x\n");
}

TEST(LoggerTest, LevelNamesFollowSyslog) {
    EXPECT_EQ(logLevelName(LogLevel::Emergency), "emerg");
    EXPECT_EQ(logLevelName(LogLevel::Critical), "crit");
    EXPECT_EQ(logLevelName(LogLevel::Error), "err");
    EXPECT_EQ(logLevelName(LogLevel::Notice), "notice");
    EXPECT_EQ(logLevelName(LogLevel::Debug), "debug");
}

TEST(LogRateLimiterTest, AdmitsFirstAndCountsSuppressed) {
    LogRateLimiter limiter(10s, 256);
    EXPECT_EQ(limiter.admit("malformed PRUNE:ab", T0), 0u);
    EXPECT_EQ(limiter.admit("malformed PRUNE:ab", T0 + 1s), std::nullopt);
    EXPECT_EQ(limiter.admit("malformed PRUNE:ab", T0 + 9s), std::nullopt);
    EXPECT_EQ(limiter.admit("malformed PRUNE:ab", T0 + 11s), 2u);
    EXPECT_EQ(limiter.admit("malformed PRUNE:ab", T0 + 12s), std::nullopt);
}

TEST(LogRateLimiterTest, KeysAreIndependent) {
    LogRateLimiter limiter(10s, 256);
    EXPECT_EQ(limiter.admit("a", T0), 0u);
    EXPECT_EQ(limiter.admit("b", T0), 0u);
    EXPECT_EQ(limiter.admit("a", T0), std::nullopt);
}

TEST(LogRateLimiterTest, EvictsLeastRecentlySeenKeyAtCap) {
    LogRateLimiter limiter(10s, 2);
    EXPECT_EQ(limiter.admit("a", T0), 0u);
    EXPECT_EQ(limiter.admit("b", T0 + 1s), 0u);
    EXPECT_EQ(limiter.admit("c", T0 + 2s), 0u);                                     // evicts "a"
    EXPECT_EQ(limiter.admit("a", T0 + 3s), 0u);                                     // forgotten, so admitted afresh (evicts "b")
    EXPECT_EQ(limiter.admit("c", T0 + 4s), std::nullopt);                           // still remembered
}

TEST(LogRateLimiterTest, SuppressedNote) {
    EXPECT_EQ(LogRateLimiter::suppressedNote(0), "");
    EXPECT_EQ(LogRateLimiter::suppressedNote(3), " (3 similar suppressed)");
}
