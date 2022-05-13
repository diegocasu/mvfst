#pragma once

#include <quic/servermigration/PoolMigrationAddressScheduler.h>
#include <set>

namespace quic {

/**
 * Default scheduler of pool migration addresses. It sorts addresses based
 * on the relational operator "<" defined by QuicIPAddress, with the exception
 * of the current server address, which is always the first address returned
 * by next() in each cycle, if set.
 * This scheduler uses an std::set to manage the addresses, thus the complexity
 * of the insert() and contain() operations is the same of insert() and count()
 * offered by std::set, respectively. The insertion of an address while cycling
 * the pool does not alter the current cycle, i.e. the insertion has effect
 * only starting from the next cycle. This rule affects also the insertion or
 * modification of the current server address.
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

  void insert(QuicIPAddress address) override;

  const QuicIPAddress& next() override;

  bool contains(const QuicIPAddress& address) override;

  void restart() override;

  void setCurrentServerAddress(QuicIPAddress address) override;

  const QuicIPAddress& getCurrentServerAddress() override;

 protected:
  QuicIPAddress currentServerAddress_;
  std::set<QuicIPAddress> pool_;
  std::set<QuicIPAddress> pendingAddresses_;
  bool iterating_{false};
  std::set<QuicIPAddress>::iterator iterator_;
};

} // namespace quic
