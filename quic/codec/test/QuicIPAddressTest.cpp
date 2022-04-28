#include <folly/portability/GTest.h>
#include <quic/codec/QuicIPAddress.h>

using namespace testing;

namespace quic {
namespace test {

class QuicIPAddressTest : public Test {
 public:
  folly::IPAddressV4 ipv4Address{"127.0.0.1"};
  uint16_t ipv4Port{5000};
  folly::SocketAddress ipv4SocketAddress{ipv4Address, ipv4Port};

  folly::IPAddressV6 ipv6Address{"::1"};
  uint16_t ipv6Port{5001};
  folly::SocketAddress ipv6SocketAddress{ipv6Address, ipv6Port};

  uint16_t emptyPort = 0;
};

TEST_F(QuicIPAddressTest, TestInitializationWithSingleFamily) {
  QuicIPAddress fromIpv4(ipv4Address, ipv4Port);
  EXPECT_EQ(fromIpv4.ipv4Address, ipv4Address);
  EXPECT_EQ(fromIpv4.ipv4Port, ipv4Port);
  EXPECT_TRUE(fromIpv4.ipv6Address.isZero());
  EXPECT_EQ(fromIpv4.ipv6Port, emptyPort);

  QuicIPAddress fromIpv4WithSockAddr(ipv4SocketAddress);
  EXPECT_EQ(fromIpv4WithSockAddr.ipv4Address, ipv4Address);
  EXPECT_EQ(fromIpv4WithSockAddr.ipv4Port, ipv4Port);
  EXPECT_TRUE(fromIpv4WithSockAddr.ipv6Address.isZero());
  EXPECT_EQ(fromIpv4WithSockAddr.ipv6Port, emptyPort);

  QuicIPAddress fromIpv6(ipv6Address, ipv6Port);
  EXPECT_TRUE(fromIpv6.ipv4Address.isZero());
  EXPECT_EQ(fromIpv6.ipv4Port, emptyPort);
  EXPECT_EQ(fromIpv6.ipv6Address, ipv6Address);
  EXPECT_EQ(fromIpv6.ipv6Port, ipv6Port);

  QuicIPAddress fromIpv6WithSockAddr(ipv6SocketAddress);
  EXPECT_TRUE(fromIpv6WithSockAddr.ipv4Address.isZero());
  EXPECT_EQ(fromIpv6WithSockAddr.ipv4Port, emptyPort);
  EXPECT_EQ(fromIpv6WithSockAddr.ipv6Address, ipv6Address);
  EXPECT_EQ(fromIpv6WithSockAddr.ipv6Port, ipv6Port);
}

TEST_F(QuicIPAddressTest, TestInitializationWithBothFamilies) {
  QuicIPAddress fromIpAddresses(ipv4Address, ipv4Port, ipv6Address, ipv6Port);
  EXPECT_EQ(fromIpAddresses.ipv4Address, ipv4Address);
  EXPECT_EQ(fromIpAddresses.ipv4Port, ipv4Port);
  EXPECT_EQ(fromIpAddresses.ipv6Address, ipv6Address);
  EXPECT_EQ(fromIpAddresses.ipv6Port, ipv6Port);

  QuicIPAddress fromSockAddresses(ipv4SocketAddress, ipv6SocketAddress);
  EXPECT_EQ(fromSockAddresses.ipv4Address, ipv4Address);
  EXPECT_EQ(fromSockAddresses.ipv4Port, ipv4Port);
  EXPECT_EQ(fromSockAddresses.ipv6Address, ipv6Address);
  EXPECT_EQ(fromSockAddresses.ipv6Port, ipv6Port);

  // Attempt to initialize a V4 address starting from a V6 one and vice-versa.
  ASSERT_DEATH(
      QuicIPAddress frameFromWrongSockAddresses(
          ipv6SocketAddress, ipv4SocketAddress),
      "\\w");
}

TEST_F(QuicIPAddressTest, TestAllZeroRepresentation) {
  QuicIPAddress notAllZero(ipv4SocketAddress, ipv6SocketAddress);
  EXPECT_FALSE(notAllZero.isAllZero());

  notAllZero = QuicIPAddress(ipv4SocketAddress);
  EXPECT_FALSE(notAllZero.isAllZero());

  QuicIPAddress allZero;
  EXPECT_TRUE(allZero.isAllZero());
}

} // namespace test
} // namespace quic
