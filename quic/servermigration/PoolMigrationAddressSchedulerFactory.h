#pragma once

#include <quic/servermigration/PoolMigrationAddressScheduler.h>

namespace quic {

class PoolMigrationAddressSchedulerFactory {
 public:
  virtual ~PoolMigrationAddressSchedulerFactory() = default;

  virtual std::shared_ptr<PoolMigrationAddressScheduler> make() = 0;
};

} // namespace quic
