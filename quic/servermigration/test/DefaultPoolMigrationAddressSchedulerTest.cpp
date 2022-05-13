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
  const std::set<QuicIPAddress>& pool() {
    return pool_;
  }
  const std::set<QuicIPAddress>& pendingAddresses() {
    return pendingAddresses_;
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
  scheduler.setCurrentServerAddress(serverAddress2);
  EXPECT_EQ(scheduler.getCurrentServerAddress(), serverAddress2);
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestSetServerAddressWithAllZero) {
  QuicIPAddress serverAddress(folly::SocketAddress("1.2.3.4", 1234));
  scheduler.setCurrentServerAddress(serverAddress);
  ASSERT_EQ(scheduler.getCurrentServerAddress(), serverAddress);
  QuicIPAddress emptyAddress;
  ASSERT_TRUE(emptyAddress.isAllZero());
  scheduler.setCurrentServerAddress(emptyAddress);
  EXPECT_EQ(scheduler.getCurrentServerAddress(), serverAddress);
}

TEST_F(DefaultPoolMigrationAddressSchedulerTest, TestGetServerAddress) {
  auto& serverAddress = scheduler.getCurrentServerAddress();
  EXPECT_TRUE(serverAddress.isAllZero());
  QuicIPAddress newServerAddress(folly::SocketAddress("1.2.3.4", 1234));
  scheduler.setCurrentServerAddress(newServerAddress);
  EXPECT_EQ(scheduler.getCurrentServerAddress(), newServerAddress);
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
  EXPECT_THROW(scheduler.next(), QuicInternalException);
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
  EXPECT_EQ(scheduler.getCurrentServerAddress(), serverAddress);
  // Continue cycling.
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
  ASSERT_EQ(scheduler.pool().size(), 3);
  ASSERT_TRUE(scheduler.pool().count(address1));
  ASSERT_TRUE(scheduler.pool().count(address2));
  ASSERT_TRUE(scheduler.pool().count(address3));
  ASSERT_TRUE(scheduler.pendingAddresses().empty());

  EXPECT_EQ(scheduler.next(), serverAddress1);
  EXPECT_EQ(scheduler.next(), address1);
  // Change server address.
  scheduler.setCurrentServerAddress(serverAddress2);
  ASSERT_EQ(scheduler.getCurrentServerAddress(), serverAddress2);
  // Continue cycling.
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);
  EXPECT_EQ(scheduler.next(), serverAddress2);
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
  EXPECT_EQ(scheduler.next(), address2);
  // Check expectations after finding address2.
  EXPECT_EQ(scheduler.pool().size(), 3);
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pool().count(address3));
  EXPECT_TRUE(scheduler.pool().count(address4));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
  // Continue cycling.
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
  EXPECT_EQ(scheduler.next(), address1);
  // Check expectations after finding address1.
  EXPECT_EQ(scheduler.pool().size(), 4);
  EXPECT_TRUE(scheduler.pool().count(address1));
  EXPECT_TRUE(scheduler.pool().count(address2));
  EXPECT_TRUE(scheduler.pool().count(address3));
  EXPECT_TRUE(scheduler.pool().count(address4));
  EXPECT_TRUE(scheduler.pendingAddresses().empty());
  // Continue cycling.
  EXPECT_EQ(scheduler.next(), address2);
  EXPECT_EQ(scheduler.next(), address3);
  EXPECT_EQ(scheduler.next(), address4);
}

} // namespace test
} // namespace quic
