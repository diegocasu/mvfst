#include "DefaultPoolMigrationAddressSchedulerFactory.h"
#include <quic/servermigration/DefaultPoolMigrationAddressScheduler.h>

namespace quic {

std::shared_ptr<PoolMigrationAddressScheduler>
DefaultPoolMigrationAddressSchedulerFactory::make() {
  return std::make_shared<DefaultPoolMigrationAddressScheduler>();
}

} // namespace quic
