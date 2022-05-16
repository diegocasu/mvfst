#pragma once

#include <quic/servermigration/PoolMigrationAddressScheduler.h>
#include <set>
#include <unordered_set>

namespace quic {

/**
 * Default scheduler of pool migration addresses. It sorts addresses based
 * on the relational operator "<" defined by QuicIPAddress, with the exception
 * of the current server address, which is always the first address returned
 * by next() in each cycle, if set.
 * This scheduler uses both an std::set and an std::unordered_set to manage
 * the addresses, thus:
 * 1) the complexity of insert() and contains(const QuicIPAddress& address) is
 * the same of insert() and count() offered by std::set, respectively;
 * 2) the complexity of contains(const folly::SocketAddress& address) is the
 * same of count() offered by std::unordered_set.
 */
class DefaultPoolMigrationAddressScheduler
    : public PoolMigrationAddressScheduler {
 public:
  ~DefaultPoolMigrationAddressScheduler() override = default;
  DefaultPoolMigrationAddressScheduler();

  DefaultPoolMigrationAddressScheduler(
      const DefaultPoolMigrationAddressScheduler&) = delete;
  DefaultPoolMigrationAddressScheduler(
      DefaultPoolMigrationAddressScheduler&& that) = delete;
  DefaultPoolMigrationAddressScheduler& operator=(
      const DefaultPoolMigrationAddressScheduler&) = delete;
  DefaultPoolMigrationAddressScheduler& operator=(
      DefaultPoolMigrationAddressScheduler&& that) = delete;

  /**
   * Inserts a new address in the scheduler, if not already present.
   * The insertion of an address while cycling the pool does not alter the
   * current cycle, i.e. the insertion has effect only starting from
   * the next cycle.
   * @param address  the address. It is ignored if all-zero.
   */
  void insert(QuicIPAddress address) override;

  /**
   * Returns the next address in the cycle, advancing it. If an address added
   * with insert() is equal to the current server address, this method
   * guarantees that it will be returned only once per cycle (at the beginning).
   * It throws a QuicInternalException exception if the scheduler is empty,
   * namely if one of the following conditions is true:
   * 1) no address has been added with insert();
   * 2) one address has been added with insert(), but it is equal to the
   * current server address.
   * @return  the next address in the cycle.
   */
  const QuicIPAddress& next() override;

  bool contains(const QuicIPAddress& address) override;

  bool contains(const folly::SocketAddress& address) override;

  void restart() override;

  /**
   * Sets the current address of the server. If a cycle is ongoing,
   * the operation is effective only starting from the next cycle.
   * @param address  the current address of the server.
   *                 If all-zero, it resets the address.
   */
  void setCurrentServerAddress(QuicIPAddress address) override;

  const QuicIPAddress& getCurrentServerAddress() override;

 protected:
  QuicIPAddress currentServerAddress_;
  QuicIPAddress pendingServerAddress_;
  std::set<QuicIPAddress> pool_;
  std::set<QuicIPAddress> pendingAddresses_;
  std::unordered_set<folly::SocketAddress> socketAddresses_;
  bool iterating_{false};
  std::set<QuicIPAddress>::iterator iterator_;
};

} // namespace quic
