#include <folly/portability/GTest.h>
#include <quic/QuicException.h>
#include <quic/servermigration/DefaultPoolMigrationAddressScheduler.h>

using namespace testing;

namespace quic {
namespace test {

class TestingDefaultPoolMigrationAddressScheduler
    : public DefaultPoolMigrationAddressScheduler {
 public:
  const QuicIPAddress& currentServerAddress() {
    return currentServerAddress_;
  }
  const QuicIPAddress pendingServerAddress() {
    return pendingServerAddress_;
  }
  const std::set<QuicIPAddress>& pool() {
    return pool_;
  }
  const std::set<QuicIPAddress>& pendingAddresses() {
    return pendingAddresses_;
  }
  const std::unordered_set<folly::SocketAddress>& socketAddresses() {
    return socketAddresses_;
  }
  bool iterating() {
    return iterating_;
  }
  std::set<QuicIPAddress>::iterator iterator() {
    return iterator_;
  }
};

class DefaultPoolMigrationAddressSchedulerTest : public Test {
 public:
  TestingDefaultPoolMigrationAddressScheduler scheduler;
};

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestSetServerAddress) {
  QuicIPAddress serverAddress1(folly::SocketAddress("1.2.3.4", 1234));
  QuicIPAddress serverAddress2(folly::SocketAddress("5.6.7.8", 5678));
  scheduler.setCurrentServerAddress(serverAddress1);
  EXPECT_EQ(scheduler.getCurrentServerAddress(), serverAddress1);
  EXPECT_EQ(scheduler.pendingServerAddress(), serverAddress1);
  scheduler.setCurrentServerAddress(serverAddress2);
  EXPECT_EQ(scheduler.getCurrentServerAddress(), serverAddress2);
  EXPECT_EQ(scheduler.pendingServerAddress(), serverAddress2);
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestSetServerAddressWithAllZero) {
  QuicIPAddress serverAddress(folly::SocketAddress("1.2.3.4", 1234));
  scheduler.setCurrentServerAddress(serverAddress);
  ASSERT_EQ(scheduler.getCurrentServerAddress(), serverAddress);
  ASSERT_EQ(scheduler.pendingServerAddress(), serverAddress);
  QuicIPAddress emptyAddress;
  ASSERT_TRUE(emptyAddress.isAllZero());
  scheduler.setCurrentServerAddress(emptyAddress);
  EXPECT_TRUE(scheduler.getCurrentServerAddress().isAllZero());
  EXPECT_TRUE(scheduler.pendingServerAddress().isAllZero());
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestGetServerAddress) {
  auto& serverAddress = scheduler.getCurrentServerAddress();
  EXPECT_TRUE(serverAddress.isAllZero());
  QuicIPAddress newServerAddress(folly::SocketAddress("1.2.3.4", 1234));
  scheduler.setCurrentServerAddress(newServerAddress);
  EXPECT_EQ(scheduler.getCurrentServerAddress(), newServerAddress);
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestInsertSocketAddresses) {
  QuicIPAddress addressWithBothVersions(
      folly::IPAddressV4("1.2.3.4"), 1234, folly::IPAddressV6("::1"), 1111);
  QuicIPAddress addressV4(folly::IPAddressV4("5.6.7.8"), 5678);
  QuicIPAddress addressV6(folly::IPAddressV6("::2"), 2222);
  ASSERT_TRUE(scheduler.socketAddresses().empty());
  scheduler.insert(addressWithBothVersions);
  scheduler.insert(addressV4);
  scheduler.insert(addressV6);
  EXPECT_EQ(scheduler.socketAddresses().size(), 4);
  EXPECT_TRUE(scheduler.socketAddresses().count(
      addressWithBothVersions.getIPv4AddressAsSocketAddress()));
  EXPECT_TRUE(scheduler.socketAddresses().count(
      addressWithBothVersions.getIPv6AddressAsSocketAddress()));
  EXPECT_TRUE(scheduler.socketAddresses().count(
      addressV4.getIPv4AddressAsSocketAddress()));
  EXPECT_TRUE(scheduler.socketAddresses().count(
      addressV6.getIPv6AddressAsSocketAddress()));
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestInsertWithAllZero) {
  ASSERT_TRUE(scheduler.pool().empty());
  ASSERT_TRUE(scheduler.pendingAddresses().empty());
  QuicIPAddress emptyAddress;
  scheduler.insert(emptyAddress);
  EXPECT_TRUE(scheduler.pool().empty());
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestInsertWhileNotIterating) {
  ASSERT_FALSE(scheduler.iterating());
  ASSERT_TRUE(scheduler.pool().empty());
  ASSERT_TRUE(scheduler.pendingAddresses().empty());
  QuicIPAddress address(folly::SocketAddress("1.2.3.4", 1234));
  scheduler.insert(address);
  EXPECT_FALSE(scheduler.iterating());
  EXPECT_EQ(scheduler.pool().size(), 1);
  EXPECT_TRUE(scheduler.pool().count(address));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestNextWithEmptyPool) {
  ASSERT_TRUE(scheduler.getCurrentServerAddress().isAllZero());
  EXPECT_THROW(scheduler.next(), QuicInternalException);
  scheduler.setCurrentServerAddress(
      QuicIPAddress(folly::SocketAddress("1.2.3.4", 1234)));
  ASSERT_FALSE(scheduler.getCurrentServerAddress().isAllZero());
  EXPECT_THROW(scheduler.next(), QuicInternalException);
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestNextWithPoolContainingOnlyCurrentServerAddress) {
  QuicIPAddress serverAddress(folly::SocketAddress("1.2.3.4", 1234));
  scheduler.insert(serverAddress);
  scheduler.setCurrentServerAddress(serverAddress);
  EXPECT_THROW(scheduler.next(), QuicInternalException);
  scheduler.setCurrentServerAddress(QuicIPAddress());
  EXPECT_NO_THROW(scheduler.next());
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestInsertWhileIterating) {
  QuicIPAddress address1(folly::SocketAddress("1.2.3.4", 1234));
  QuicIPAddress address2(folly::SocketAddress("5.6.7.8", 5678));
  scheduler.insert(address1);
  scheduler.insert(address2);
  scheduler.next();
  ASSERT_TRUE(scheduler.iterating());
  ASSERT_EQ(scheduler.pool().size(), 2);
  ASSERT_TRUE(scheduler.pool().count(address1));
  ASSERT_TRUE(scheduler.pool().count(address2));
  ASSERT_TRUE(scheduler.pendingAddresses().empty());

  QuicIPAddress address3(folly::SocketAddress("9.10.11.12", 3132));
  scheduler.insert(address3);
  EXPECT_TRUE(scheduler.iterating());
  EXPECT_EQ(scheduler.pool().size(), 2);
  EXPECT_TRUE(scheduler.pool().count(address1));
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_EQ(scheduler.pendingAddresses().size(), 1);
  EXPECT_TRUE(scheduler.pendingAddresses().count(address3));
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestInsertDuplicate) {
  QuicIPAddress address1(folly::SocketAddress("1.2.3.4", 1234));
  QuicIPAddress address2(folly::SocketAddress("5.6.7.8", 5678));
  scheduler.insert(address1);
  scheduler.insert(address2);
  ASSERT_FALSE(scheduler.iterating());
  ASSERT_EQ(scheduler.pool().size(), 2);
  ASSERT_TRUE(scheduler.pool().count(address1));
  ASSERT_TRUE(scheduler.pool().count(address2));
  ASSERT_TRUE(scheduler.pendingAddresses().empty());

  // Test while not iterating.
  scheduler.insert(address1);
  ASSERT_FALSE(scheduler.iterating());
  EXPECT_EQ(scheduler.pool().size(), 2);
  EXPECT_TRUE(scheduler.pool().count(address1));
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());

  // Test while iterating.
  scheduler.next();
  scheduler.insert(address1);
  ASSERT_TRUE(scheduler.iterating());
  EXPECT_EQ(scheduler.pool().size(), 2);
  EXPECT_TRUE(scheduler.pool().count(address1));
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestCycleWithServerAddress) {
  QuicIPAddress serverAddress(folly::SocketAddress("10.10.10.10", 1010));
  QuicIPAddress address1(folly::SocketAddress("1.1.1.1", 1111));
  QuicIPAddress address2(folly::SocketAddress("2.2.2.2", 2222));
  QuicIPAddress address3(folly::SocketAddress("3.3.3.3", 3333));
  scheduler.insert(address3);
  scheduler.insert(address2);
  scheduler.insert(address1);
  scheduler.setCurrentServerAddress(serverAddress);
  ASSERT_EQ(scheduler.getCurrentServerAddress(), serverAddress);
  ASSERT_EQ(scheduler.pool().size(), 3);
  ASSERT_TRUE(scheduler.pool().count(address1));
  ASSERT_TRUE(scheduler.pool().count(address2));
  ASSERT_TRUE(scheduler.pool().count(address3));
  ASSERT_TRUE(scheduler.pendingAddresses().empty());

  // Perform two complete cycles.
  EXPECT_EQ(scheduler.next(), serverAddress);
  EXPECT_EQ(scheduler.next(), address1);
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);
  EXPECT_EQ(scheduler.next(), serverAddress);
  EXPECT_EQ(scheduler.next(), address1);
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);

  EXPECT_EQ(scheduler.pool().size(), 3);
  EXPECT_TRUE(scheduler.pool().count(address1));
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pool().count(address3));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestCycleWithoutServerAddress) {
  QuicIPAddress address1(folly::SocketAddress("1.1.1.1", 1111));
  QuicIPAddress address2(folly::SocketAddress("2.2.2.2", 2222));
  QuicIPAddress address3(folly::SocketAddress("3.3.3.3", 3333));
  scheduler.insert(address3);
  scheduler.insert(address2);
  scheduler.insert(address1);
  ASSERT_TRUE(scheduler.getCurrentServerAddress().isAllZero());
  ASSERT_EQ(scheduler.pool().size(), 3);
  ASSERT_TRUE(scheduler.pool().count(address1));
  ASSERT_TRUE(scheduler.pool().count(address2));
  ASSERT_TRUE(scheduler.pool().count(address3));
  ASSERT_TRUE(scheduler.pendingAddresses().empty());

  // Perform two complete cycles.
  EXPECT_EQ(scheduler.next(), address1);
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);
  EXPECT_EQ(scheduler.next(), address1);
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);

  EXPECT_TRUE(scheduler.getCurrentServerAddress().isAllZero());
  EXPECT_EQ(scheduler.pool().size(), 3);
  EXPECT_TRUE(scheduler.pool().count(address1));
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pool().count(address3));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestAvoidSchedulingTwiceWhenPoolAddressIsAlsoCurrentServerAddress) {
  QuicIPAddress address1(folly::SocketAddress("1.1.1.1", 1111));
  QuicIPAddress address2(folly::SocketAddress("2.2.2.2", 2222));
  QuicIPAddress address3(folly::SocketAddress("3.3.3.3", 3333));
  scheduler.insert(address3);
  scheduler.insert(address2);
  scheduler.insert(address1);
  scheduler.setCurrentServerAddress(address3);

  ASSERT_EQ(scheduler.getCurrentServerAddress(), address3);
  ASSERT_EQ(scheduler.pendingServerAddress(), address3);
  ASSERT_EQ(scheduler.pool().size(), 3);
  ASSERT_TRUE(scheduler.pool().count(address1));
  ASSERT_TRUE(scheduler.pool().count(address2));
  ASSERT_TRUE(scheduler.pool().count(address3));
  ASSERT_TRUE(scheduler.pendingAddresses().empty());

  // Perform two complete cycles.
  EXPECT_EQ(scheduler.next(), address3);
  EXPECT_EQ(scheduler.next(), address1);
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);
  EXPECT_EQ(scheduler.next(), address1);
  EXPECT_EQ(scheduler.next(), address2);

  EXPECT_EQ(scheduler.pool().size(), 3);
  EXPECT_TRUE(scheduler.pool().count(address1));
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pool().count(address3));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestAvoidNoSchedulingWhenPoolAddressIsAlsoCurrentServerAddress) {
  QuicIPAddress address1(folly::SocketAddress("1.1.1.1", 1111));
  QuicIPAddress address2(folly::SocketAddress("2.2.2.2", 2222));
  QuicIPAddress address3(folly::SocketAddress("3.3.3.3", 3333));
  scheduler.insert(address3);
  scheduler.insert(address2);
  scheduler.insert(address1);

  ASSERT_TRUE(scheduler.getCurrentServerAddress().isAllZero());
  ASSERT_TRUE(scheduler.pendingServerAddress().isAllZero());
  ASSERT_EQ(scheduler.pool().size(), 3);
  ASSERT_TRUE(scheduler.pool().count(address1));
  ASSERT_TRUE(scheduler.pool().count(address2));
  ASSERT_TRUE(scheduler.pool().count(address3));
  ASSERT_TRUE(scheduler.pendingAddresses().empty());

  // Perform two complete cycles. In the first one, the current server
  // address is set to be address3, so equal to an address of the pool, while
  // iterating: this should not cancel the scheduling of address3 as last
  // address, because the setting was done during the cycle.
  // In the second one, the setting should be applied, so address3 should
  // appear only once and as the first element.
  EXPECT_EQ(scheduler.next(), address1);
  scheduler.setCurrentServerAddress(address3);
  EXPECT_TRUE(scheduler.getCurrentServerAddress().isAllZero());
  EXPECT_EQ(scheduler.pendingServerAddress(), address3);
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);

  EXPECT_EQ(scheduler.next(), address3);
  EXPECT_EQ(scheduler.getCurrentServerAddress(), address3);
  EXPECT_EQ(scheduler.pendingServerAddress(), address3);
  EXPECT_EQ(scheduler.next(), address1);
  EXPECT_EQ(scheduler.next(), address2);

  EXPECT_EQ(scheduler.pool().size(), 3);
  EXPECT_TRUE(scheduler.pool().count(address1));
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pool().count(address3));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestAvoidSchedulingTwiceWhenCurrentServerAddressIsGoingToBeReplaced) {
  QuicIPAddress address1(folly::SocketAddress("1.1.1.1", 1111));
  QuicIPAddress address2(folly::SocketAddress("2.2.2.2", 2222));
  QuicIPAddress address3(folly::SocketAddress("3.3.3.3", 3333));
  scheduler.insert(address3);
  scheduler.insert(address2);
  scheduler.insert(address1);
  scheduler.setCurrentServerAddress(address3);

  ASSERT_EQ(scheduler.getCurrentServerAddress(), address3);
  ASSERT_EQ(scheduler.pendingServerAddress(), address3);
  ASSERT_EQ(scheduler.pool().size(), 3);
  ASSERT_TRUE(scheduler.pool().count(address1));
  ASSERT_TRUE(scheduler.pool().count(address2));
  ASSERT_TRUE(scheduler.pool().count(address3));
  ASSERT_TRUE(scheduler.pendingAddresses().empty());

  // Perform two complete cycles. In the first one, the current server address
  // (address3) is replaced while iterating, but nonetheless address3 should
  // never be scheduled twice during the same cycle.
  EXPECT_EQ(scheduler.next(), address3);
  scheduler.setCurrentServerAddress(QuicIPAddress());
  EXPECT_EQ(scheduler.getCurrentServerAddress(), address3);
  EXPECT_TRUE(scheduler.pendingServerAddress().isAllZero());
  EXPECT_EQ(scheduler.next(), address1);
  EXPECT_EQ(scheduler.next(), address2);

  EXPECT_EQ(scheduler.next(), address1);
  EXPECT_TRUE(scheduler.getCurrentServerAddress().isAllZero());
  EXPECT_TRUE(scheduler.pendingServerAddress().isAllZero());
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);

  EXPECT_EQ(scheduler.pool().size(), 3);
  EXPECT_TRUE(scheduler.pool().count(address1));
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pool().count(address3));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestSetServerAddressWhileIterating) {
  QuicIPAddress serverAddress(folly::SocketAddress("10.10.10.10", 1010));
  QuicIPAddress address1(folly::SocketAddress("1.1.1.1", 1111));
  QuicIPAddress address2(folly::SocketAddress("2.2.2.2", 2222));
  QuicIPAddress address3(folly::SocketAddress("3.3.3.3", 3333));
  scheduler.insert(address3);
  scheduler.insert(address2);
  scheduler.insert(address1);
  ASSERT_TRUE(scheduler.getCurrentServerAddress().isAllZero());
  ASSERT_EQ(scheduler.pool().size(), 3);
  ASSERT_TRUE(scheduler.pool().count(address1));
  ASSERT_TRUE(scheduler.pool().count(address2));
  ASSERT_TRUE(scheduler.pool().count(address3));
  ASSERT_TRUE(scheduler.pendingAddresses().empty());

  EXPECT_EQ(scheduler.next(), address1);
  // Set server address.
  scheduler.setCurrentServerAddress(serverAddress);
  EXPECT_TRUE(scheduler.getCurrentServerAddress().isAllZero());
  EXPECT_EQ(scheduler.pendingServerAddress(), serverAddress);
  // Continue cycling.
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);
  EXPECT_EQ(scheduler.next(), serverAddress);
  EXPECT_EQ(scheduler.getCurrentServerAddress(), serverAddress);
  EXPECT_EQ(scheduler.pendingServerAddress(), serverAddress);
  EXPECT_EQ(scheduler.next(), address1);
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);

  EXPECT_EQ(scheduler.pool().size(), 3);
  EXPECT_TRUE(scheduler.pool().count(address1));
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pool().count(address3));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestChangeServerAddressWhileIterating) {
  QuicIPAddress serverAddress1(folly::SocketAddress("10.10.10.10", 1010));
  QuicIPAddress serverAddress2(folly::SocketAddress("11.11.11.11", 1212));
  QuicIPAddress address1(folly::SocketAddress("1.1.1.1", 1111));
  QuicIPAddress address2(folly::SocketAddress("2.2.2.2", 2222));
  QuicIPAddress address3(folly::SocketAddress("3.3.3.3", 3333));
  scheduler.insert(address3);
  scheduler.insert(address2);
  scheduler.insert(address1);
  scheduler.setCurrentServerAddress(serverAddress1);
  ASSERT_EQ(scheduler.getCurrentServerAddress(), serverAddress1);
  ASSERT_EQ(scheduler.pendingServerAddress(), serverAddress1);
  ASSERT_EQ(scheduler.pool().size(), 3);
  ASSERT_TRUE(scheduler.pool().count(address1));
  ASSERT_TRUE(scheduler.pool().count(address2));
  ASSERT_TRUE(scheduler.pool().count(address3));
  ASSERT_TRUE(scheduler.pendingAddresses().empty());

  EXPECT_EQ(scheduler.next(), serverAddress1);
  EXPECT_EQ(scheduler.next(), address1);
  // Change server address.
  scheduler.setCurrentServerAddress(serverAddress2);
  EXPECT_EQ(scheduler.getCurrentServerAddress(), serverAddress1);
  EXPECT_EQ(scheduler.pendingServerAddress(), serverAddress2);
  // Continue cycling.
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);
  EXPECT_EQ(scheduler.next(), serverAddress2);
  EXPECT_EQ(scheduler.getCurrentServerAddress(), serverAddress2);
  EXPECT_EQ(scheduler.pendingServerAddress(), serverAddress2);
  EXPECT_EQ(scheduler.next(), address1);
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);

  EXPECT_EQ(scheduler.pool().size(), 3);
  EXPECT_TRUE(scheduler.pool().count(address1));
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pool().count(address3));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestRestart) {
  QuicIPAddress serverAddress(folly::SocketAddress("10.10.10.10", 1010));
  QuicIPAddress address1(folly::SocketAddress("1.1.1.1", 1111));
  QuicIPAddress address2(folly::SocketAddress("2.2.2.2", 2222));
  QuicIPAddress address3(folly::SocketAddress("3.3.3.3", 3333));
  scheduler.insert(address3);
  scheduler.insert(address2);
  scheduler.insert(address1);
  scheduler.setCurrentServerAddress(serverAddress);
  ASSERT_EQ(scheduler.getCurrentServerAddress(), serverAddress);
  ASSERT_EQ(scheduler.pool().size(), 3);
  ASSERT_TRUE(scheduler.pool().count(address1));
  ASSERT_TRUE(scheduler.pool().count(address2));
  ASSERT_TRUE(scheduler.pool().count(address3));
  ASSERT_TRUE(scheduler.pendingAddresses().empty());

  EXPECT_EQ(scheduler.next(), serverAddress);
  EXPECT_EQ(scheduler.next(), address1);
  EXPECT_EQ(scheduler.next(), address2);
  scheduler.restart();
  EXPECT_FALSE(scheduler.iterating());
  EXPECT_EQ(scheduler.next(), serverAddress);
  EXPECT_EQ(scheduler.next(), address1);
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);

  EXPECT_EQ(scheduler.pool().size(), 3);
  EXPECT_TRUE(scheduler.pool().count(address1));
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pool().count(address3));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestMergePendingAddresses) {
  QuicIPAddress serverAddress(folly::SocketAddress("10.10.10.10", 1010));
  QuicIPAddress address1(folly::SocketAddress("1.1.1.1", 1111));
  QuicIPAddress address2(folly::SocketAddress("2.2.2.2", 2222));
  QuicIPAddress address3(folly::SocketAddress("3.3.3.3", 3333));
  QuicIPAddress address4(folly::SocketAddress("4.4.4.4", 4444));

  scheduler.insert(address4);
  scheduler.insert(address3);
  scheduler.setCurrentServerAddress(serverAddress);
  ASSERT_EQ(scheduler.getCurrentServerAddress(), serverAddress);
  ASSERT_EQ(scheduler.pool().size(), 2);
  ASSERT_TRUE(scheduler.pool().count(address3));
  ASSERT_TRUE(scheduler.pool().count(address4));
  ASSERT_TRUE(scheduler.pendingAddresses().empty());

  // Insert while iterating and expect merge at the beginning of the next cycle.
  EXPECT_EQ(scheduler.next(), serverAddress);
  EXPECT_EQ(scheduler.next(), address3);
  // Insert.
  scheduler.insert(address2);
  EXPECT_EQ(scheduler.pool().size(), 2);
  EXPECT_TRUE(scheduler.pool().count(address3));
  EXPECT_TRUE(scheduler.pool().count(address4));
  EXPECT_EQ(scheduler.pendingAddresses().size(), 1);
  EXPECT_TRUE(scheduler.pendingAddresses().count(address2));
  // Continue cycling.
  EXPECT_EQ(scheduler.next(), address4);
  EXPECT_EQ(scheduler.next(), serverAddress);
  // Check expectations after new cycle has started.
  EXPECT_EQ(scheduler.pool().size(), 3);
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pool().count(address3));
  EXPECT_TRUE(scheduler.pool().count(address4));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
  // Continue cycling.
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);
  EXPECT_EQ(scheduler.next(), address4);

  // Insert while iterating and expect merge due to a restart.
  EXPECT_EQ(scheduler.next(), serverAddress);
  EXPECT_EQ(scheduler.next(), address2);
  // Insert.
  scheduler.insert(address1);
  EXPECT_EQ(scheduler.pool().size(), 3);
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pool().count(address3));
  EXPECT_TRUE(scheduler.pool().count(address4));
  EXPECT_EQ(scheduler.pendingAddresses().size(), 1);
  EXPECT_TRUE(scheduler.pendingAddresses().count(address1));
  // Restart.
  scheduler.restart();
  EXPECT_EQ(scheduler.next(), serverAddress);
  // Check expectations after new cycle has started.
  EXPECT_EQ(scheduler.pool().size(), 4);
  EXPECT_TRUE(scheduler.pool().count(address1));
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pool().count(address3));
  EXPECT_TRUE(scheduler.pool().count(address4));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
  // Continue cycling.
  EXPECT_EQ(scheduler.next(), address1);
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);
  EXPECT_EQ(scheduler.next(), address4);
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestContainsQuicIPAddress) {
  QuicIPAddress address1(folly::SocketAddress("1.1.1.1", 1111));
  QuicIPAddress address2(folly::SocketAddress("2.2.2.2", 2222));
  QuicIPAddress address3(folly::SocketAddress("3.3.3.3", 3333));
  ASSERT_FALSE(scheduler.contains(address1));
  ASSERT_FALSE(scheduler.contains(address2));
  ASSERT_FALSE(scheduler.contains(address3));

  // Insert addresses before cycling, so that they end up inside pool_.
  scheduler.insert(address1);
  scheduler.insert(address2);
  ASSERT_EQ(scheduler.pool().size(), 2);
  ASSERT_TRUE(scheduler.pool().count(address1));
  ASSERT_TRUE(scheduler.pool().count(address2));
  ASSERT_TRUE(scheduler.pendingAddresses().empty());
  EXPECT_TRUE(scheduler.contains(address1));
  EXPECT_TRUE(scheduler.contains(address2));

  // Insert addresses while cycling, so that they
  // end up inside pendingAddresses_.
  scheduler.next();
  scheduler.insert(address3);
  ASSERT_EQ(scheduler.pool().size(), 2);
  ASSERT_TRUE(scheduler.pool().count(address1));
  ASSERT_TRUE(scheduler.pool().count(address2));
  ASSERT_EQ(scheduler.pendingAddresses().size(), 1);
  ASSERT_TRUE(scheduler.pendingAddresses().count(address3));
  EXPECT_TRUE(scheduler.contains(address3));
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestContainsSocketAddress) {
  folly::SocketAddress address1("1.1.1.1", 1111);
  folly::SocketAddress address2("2.2.2.2", 2222);
  folly::SocketAddress address3("::5", 5555);
  ASSERT_FALSE(scheduler.contains(address1));
  ASSERT_FALSE(scheduler.contains(address2));
  ASSERT_FALSE(scheduler.contains(address3));

  // Insert addresses before cycling.
  scheduler.insert(QuicIPAddress(address1));
  scheduler.insert(QuicIPAddress(address2));
  ASSERT_EQ(scheduler.socketAddresses().size(), 2);
  ASSERT_TRUE(scheduler.socketAddresses().count(address1));
  ASSERT_TRUE(scheduler.socketAddresses().count(address2));
  EXPECT_TRUE(scheduler.contains(address1));
  EXPECT_TRUE(scheduler.contains(address2));

  // Insert addresses while cycling.
  scheduler.next();
  scheduler.insert(QuicIPAddress(address3));
  ASSERT_EQ(scheduler.socketAddresses().size(), 3);
  ASSERT_TRUE(scheduler.socketAddresses().count(address1));
  ASSERT_TRUE(scheduler.socketAddresses().count(address2));
  ASSERT_TRUE(scheduler.socketAddresses().count(address3));
  EXPECT_TRUE(scheduler.contains(address3));
}

} // namespace test
} // namespace quic
