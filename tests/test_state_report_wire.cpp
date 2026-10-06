#include <gtest/gtest.h>
#include "meshlink/state_report_wire.h"

using namespace invilite::Mesh;
using namespace invilite::Mesh::StateReportWire;

namespace {

PeerId peerId(uint8_t fill) { PeerId id; id.fill(fill); return id; }

uint16_t counterId(StateCounter counter) { return static_cast<uint16_t>(counter); }

StateReport fullReport() {
    StateReport report;
    report.queryMsgId = 0x1122334455667788ULL;
    report.node       = NodeState{ "node-a", 1, 3'600'000, 1'800'000'000'123ULL, 7 };
    report.neighbors  = std::vector<NeighborState>{
        { peerId(0x01), true,  true,  120, 10'000, 20'000, 0 },
        { peerId(0x02), false, false, 5,   300,    400,    1'500 },
    };
    report.plumtree   = Counters{ { counterId(StateCounter::GraftsSent), 3 }, { counterId(StateCounter::EagerLinks), 1 } };
    report.routes     = RoutesState{ 2, 0, {
        { peerId(0x0A), peerId(0x01), 2, 1, 42u,          1'000 },
        { peerId(0x0B), peerId(0x02), 3, 0, std::nullopt, 0 },
    } };
    report.delivery   = Counters{ { counterId(StateCounter::LocalFloods), 9 } };
    report.network    = NetworkState{ { { counterId(StateCounter::ActiveInbound), 4 } }, { "203.0.113.7", "2001:db8::1" } };
    return report;
}

// Appends one raw section to an encoded report
void appendSection(std::vector<uint8_t>& payload, uint8_t type, const std::vector<uint8_t>& value) {
    payload.push_back(type);
    for (int shift = 24; shift >= 0; shift -= 8) payload.push_back(static_cast<uint8_t>(value.size() >> shift));
    payload.insert(payload.end(), value.begin(), value.end());
}

} // namespace

TEST(StateReportWireTest, QueryRoundTripsAndRequiresExactLength) {
    const StateQuery query{ static_cast<uint16_t>(sectionBit(StateSection::Neighbors) | sectionBit(StateSection::Routes)), 100, 50 };
    const std::vector<uint8_t> payload = encodeQuery(query);
    EXPECT_EQ(payload.size(), 6u);
    StateQuery decoded;
    ASSERT_TRUE(decodeQuery(payload, decoded));
    EXPECT_EQ(decoded, query);

    std::vector<uint8_t> longer = payload;
    longer.push_back(0);
    EXPECT_FALSE(decodeQuery(longer, decoded));
    EXPECT_FALSE(decodeQuery(std::span(payload).first(5), decoded));
}

TEST(StateReportWireTest, FullReportRoundTrips) {
    const StateReport report = fullReport();
    StateReport decoded;
    ASSERT_TRUE(decodeReport(encodeReport(report), decoded));
    EXPECT_EQ(decoded, report);
}

TEST(StateReportWireTest, ReportWithoutSectionsRoundTrips) {
    StateReport report;
    report.queryMsgId = 5;
    const std::vector<uint8_t> payload = encodeReport(report);
    EXPECT_EQ(payload.size(), 10u);                                                           // msgId + version + flags
    StateReport decoded;
    ASSERT_TRUE(decodeReport(payload, decoded));
    EXPECT_EQ(decoded, report);
}

// A newer node reports more than this build knows: unknown section types are skipped, unknown counter ids kept
TEST(StateReportWireTest, UnknownSectionIsSkippedAndUnknownCounterKept) {
    StateReport report;
    report.delivery = Counters{ { 0x0FFF, 77 } };
    std::vector<uint8_t> payload = encodeReport(report);
    appendSection(payload, 0x2A, { 1, 2, 3 });

    StateReport decoded;
    ASSERT_TRUE(decodeReport(payload, decoded));
    EXPECT_EQ(decoded, report);
}

TEST(StateReportWireTest, MalformedReportsAreRefused) {
    StateReport decoded;
    const std::vector<uint8_t> valid = encodeReport(fullReport());
    ASSERT_TRUE(decodeReport(valid, decoded));

    EXPECT_FALSE(decodeReport(std::span(valid).first(9), decoded));                          // header cut
    EXPECT_FALSE(decodeReport(std::span(valid).first(valid.size() - 1), decoded));           // last section cut

    StateReport onlyNode;
    onlyNode.node = NodeState{ "n", 1, 2, 3, 4 };
    std::vector<uint8_t> repeated = encodeReport(onlyNode);
    const std::vector<uint8_t> nodeSection(repeated.begin() + 10, repeated.end());
    repeated.insert(repeated.end(), nodeSection.begin(), nodeSection.end());
    EXPECT_FALSE(decodeReport(repeated, decoded));                                            // the same section twice

    std::vector<uint8_t> trailing = encodeReport(StateReport{});
    appendSection(trailing, static_cast<uint8_t>(StateSection::Delivery), { 0, 0, 0xFF });   // count 0, then a stray byte
    EXPECT_FALSE(decodeReport(trailing, decoded));

    std::vector<uint8_t> badCount = encodeReport(StateReport{});
    appendSection(badCount, static_cast<uint8_t>(StateSection::Neighbors), { 0, 5 });        // claims 5 neighbors, carries none
    EXPECT_FALSE(decodeReport(badCount, decoded));
}

// The size limit leaves out a section that does not fit and says so; the rest still arrives
TEST(StateReportWireTest, SectionOverLimitIsLeftOutAndMarked) {
    StateReport report = fullReport();
    report.routes->routes.assign(2000, RouteState{ peerId(0x0C), peerId(0x01), 4, 0, 10u, 0 });   // ~150 KB
    const std::vector<uint8_t> payload = encodeReport(report, 64 * 1024);
    EXPECT_LE(payload.size(), 64u * 1024);

    StateReport decoded;
    ASSERT_TRUE(decodeReport(payload, decoded));
    EXPECT_TRUE(decoded.truncated);
    EXPECT_FALSE(decoded.routes.has_value());
    EXPECT_EQ(decoded.node, report.node);
    EXPECT_EQ(decoded.neighbors, report.neighbors);
    EXPECT_EQ(decoded.network, report.network);                                               // sections after the dropped one still fit

    StateReport fits;
    ASSERT_TRUE(decodeReport(encodeReport(report), fits));                                    // the default 256 KB holds it
    EXPECT_FALSE(fits.truncated);
    EXPECT_EQ(fits.routes, report.routes);
}

TEST(StateReportWireTest, OverlongNameIsCut) {
    StateReport report;
    report.node = NodeState{ std::string(300, 'x'), 1, 0, 0, 0 };
    StateReport decoded;
    ASSERT_TRUE(decodeReport(encodeReport(report), decoded));
    EXPECT_EQ(decoded.node->name, std::string(255, 'x'));
}
