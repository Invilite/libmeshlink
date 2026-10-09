#include <gtest/gtest.h>
#include "meshlink/probe_scheduler.h"

using namespace invilite::Mesh;
using namespace std::chrono_literals;

namespace {

const auto T0 = std::chrono::steady_clock::time_point(std::chrono::seconds(10'000));

PeerId peerId(uint8_t fill) { PeerId id; id.fill(fill); return id; }

const PeerId A = peerId(0xA), B = peerId(0xB), C = peerId(0xC);

using Probe = ProbeScheduler::Probe;

ProbeSchedulerConfig config(double probesPerSecond = 5) {
    ProbeSchedulerConfig c;
    c.probesPerSecond = probesPerSecond;
    return c;
}

} // namespace

// An active destination's routes are measured (never measured first) and again after activeProbeInterval
TEST(ProbeSchedulerTest, RoutesOfActiveDestinationAreMeasuredPeriodically) {
    const PeerId dest = peerId(0xD0);
    RouteTable routes;
    routes.learn(dest, A, 2, T0);
    routes.recordMeasurement(dest, B, 3, 40ms, T0);
    ProbeScheduler scheduler(config());
    scheduler.noteTraffic(dest, T0);
    // Busy: no background scan in the way
    for (int i = 0; i < 200; ++i) scheduler.noteTraffic(peerId(0x50), T0);

    EXPECT_EQ(scheduler.takeDueProbes(T0, routes), (std::vector<Probe>{ { dest, A } }));
    EXPECT_TRUE(scheduler.takeDueProbes(T0 + 1s, routes).empty());                           // A in flight, B fresh
    scheduler.noteProbeFinished(dest, A);
    routes.recordMeasurement(dest, A, 2, 30ms, T0 + 1s);

    const auto later = T0 + 30500ms;
    scheduler.noteTraffic(dest, later);
    for (int i = 0; i < 200; ++i) scheduler.noteTraffic(peerId(0x50), later);
    EXPECT_EQ(scheduler.takeDueProbes(later, routes), (std::vector<Probe>{ { dest, B } }));   // 30.5 s old; A only 29.5
}

TEST(ProbeSchedulerTest, ProbesPerSecondIsAHardLimit) {
    RouteTable routes;
    ProbeScheduler scheduler(config(2));
    for (uint8_t d = 0; d < 5; ++d) {
        routes.learn(peerId(0xD0 + d), A, 2, T0);
        scheduler.noteTraffic(peerId(0xD0 + d), T0);
    }
    EXPECT_EQ(scheduler.takeDueProbes(T0, routes).size(), 2u);
    EXPECT_TRUE(scheduler.takeDueProbes(T0 + 100ms, routes).empty());
    EXPECT_EQ(scheduler.takeDueProbes(T0 + 600ms, routes).size(), 1u);                        // half a second: one more
    EXPECT_EQ(scheduler.takeDueProbes(T0 + 5s, routes).size(), 2u);                           // saved up for one second at most
}

TEST(ProbeSchedulerTest, UrgentBeforeActiveBeforeBackground) {
    const PeerId urgent = peerId(0x01), active = peerId(0x02), idle = peerId(0x03);
    RouteTable routes;
    for (const PeerId& dest : { idle, active, urgent }) routes.learn(dest, A, 2, T0);
    ProbeScheduler scheduler(config(1));
    scheduler.noteTraffic(active, T0);
    scheduler.noteUrgent(urgent);

    EXPECT_EQ(scheduler.takeDueProbes(T0, routes), (std::vector<Probe>{ { urgent, A } }));
    EXPECT_EQ(scheduler.takeDueProbes(T0 + 1s, routes), (std::vector<Probe>{ { active, A } }));
    EXPECT_EQ(scheduler.takeDueProbes(T0 + 2s, routes), (std::vector<Probe>{ { idle, A } }));
}

// Urgent measures every route of the destination at once, even one measured a moment ago
TEST(ProbeSchedulerTest, UrgentMeasuresEveryRouteNow) {
    const PeerId dest = peerId(0xD0);
    RouteTable routes;
    routes.recordMeasurement(dest, A, 2, 10ms, T0);
    routes.learn(dest, B, 3, T0);
    ProbeScheduler scheduler(config());
    scheduler.noteUrgent(dest);
    const auto probes = scheduler.takeDueProbes(T0 + 1s, routes);
    EXPECT_EQ(probes.size(), 2u);
}

// The background measures known routes only while traffic is low
TEST(ProbeSchedulerTest, BackgroundOnlyWhileTrafficIsLow) {
    RouteTable routes;
    routes.learn(peerId(0xD0), A, 2, T0);
    ProbeScheduler busy(config());
    for (int i = 0; i < 200; ++i) busy.noteTraffic(peerId(0x50), T0);                         // 20 messages/s over 10 s
    EXPECT_TRUE(busy.takeDueProbes(T0, routes).empty());

    ProbeScheduler quiet(config());
    for (int i = 0; i < 50; ++i) quiet.noteTraffic(peerId(0x50), T0);                          // 5 messages/s
    EXPECT_EQ(quiet.takeDueProbes(T0, routes), (std::vector<Probe>{ { peerId(0xD0), A } }));
    quiet.noteProbeFinished(peerId(0xD0), A);
    routes.recordMeasurement(peerId(0xD0), A, 2, 20ms, T0);
    EXPECT_TRUE(quiet.takeDueProbes(T0 + 9min, routes).empty());                               // measured within 10 min
    EXPECT_EQ(quiet.takeDueProbes(T0 + 11min, routes).size(), 1u);
}

// One probe in flight per route; it is freed when it finishes or times out
TEST(ProbeSchedulerTest, ProbeInFlightIsNotRepeated) {
    const PeerId dest = peerId(0xD0);
    RouteTable routes;
    routes.learn(dest, A, 2, T0);
    ProbeScheduler scheduler(config());
    scheduler.noteUrgent(dest);
    ASSERT_EQ(scheduler.takeDueProbes(T0, routes).size(), 1u);
    scheduler.noteUrgent(dest);
    EXPECT_TRUE(scheduler.takeDueProbes(T0 + 1s, routes).empty());
    scheduler.noteUrgent(dest);
    EXPECT_EQ(scheduler.takeDueProbes(T0 + 6s, routes).size(), 1u);                           // probeTimeout freed it
}

TEST(ProbeSchedulerTest, DisabledSchedulesNothing) {
    RouteTable routes;
    routes.learn(peerId(0xD0), A, 2, T0);
    ProbeSchedulerConfig off = config();
    off.enabled = false;
    ProbeScheduler scheduler(off);
    scheduler.noteUrgent(peerId(0xD0));
    EXPECT_TRUE(scheduler.takeDueProbes(T0, routes).empty());
}
