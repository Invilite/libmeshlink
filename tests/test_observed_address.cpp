#include <gtest/gtest.h>
#include "meshlink/observed_address.h"

using namespace invilite::Mesh;

TEST(ObservedAddressCodecTest, RoundTripsIpv4AndIpv6) {
    EXPECT_EQ(ObservedAddressCodec::encode("203.0.113.7"), (std::vector<uint8_t>{ 4, 203, 0, 113, 7 }));
    EXPECT_EQ(ObservedAddressCodec::decode(ObservedAddressCodec::encode("203.0.113.7")), "203.0.113.7");
    EXPECT_EQ(ObservedAddressCodec::encode("2a01:4f8::1").size(), 17u);
    EXPECT_EQ(ObservedAddressCodec::decode(ObservedAddressCodec::encode("2a01:4f8::1")), "2a01:4f8::1");
}

TEST(ObservedAddressCodecTest, RefusesWhatIsNotAnAddress) {
    EXPECT_TRUE(ObservedAddressCodec::encode("").empty());
    EXPECT_TRUE(ObservedAddressCodec::encode("mail.example.org").empty());
    EXPECT_FALSE(ObservedAddressCodec::decode(std::vector<uint8_t>{ 4, 1, 2, 3 }));          // short
    EXPECT_FALSE(ObservedAddressCodec::decode(std::vector<uint8_t>{ 4, 1, 2, 3, 4, 5 }));    // long
    EXPECT_FALSE(ObservedAddressCodec::decode(std::vector<uint8_t>{ 5, 1, 2, 3, 4 }));       // unknown family
    EXPECT_FALSE(ObservedAddressCodec::decode(std::vector<uint8_t>{ 6, 1, 2, 3, 4 }));       // IPv6 family, IPv4 length
}
