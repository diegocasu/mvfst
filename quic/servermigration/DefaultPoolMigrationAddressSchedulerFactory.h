#pragma once

#include <quic/servermigration/PoolMigrationAddressSchedulerFactory.h>

namespace quic {

class DefaultPoolMigrationAddressSchedulerFactory
    : public PoolMigrationAddressSchedulerFactory {
 public:
  ~DefaultPoolMigrationAddressSchedulerFactory() override = default;

  std::shared_ptr<PoolMigrationAddressScheduler> make() override;
};

} // namespace quic
