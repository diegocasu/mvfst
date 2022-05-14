#include "DefaultPoolMigrationAddressScheduler.h"
#include <quic/QuicException.h>

namespace quic {

DefaultPoolMigrationAddressScheduler::DefaultPoolMigrationAddressScheduler() {
  iterator_ = pool_.cend();
}

void DefaultPoolMigrationAddressScheduler::setCurrentServerAddress(
    QuicIPAddress address) {
  if (!address.isAllZero()) {
    currentServerAddress_ = std::move(address);
  }
}

const QuicIPAddress&
DefaultPoolMigrationAddressScheduler::getCurrentServerAddress() {
  return currentServerAddress_;
}

bool DefaultPoolMigrationAddressScheduler::contains(
    const QuicIPAddress& address) {
  return pool_.count(address);
}

void DefaultPoolMigrationAddressScheduler::insert(QuicIPAddress address) {
  if (address.isAllZero()) {
    return;
  }
  if (!iterating_) {
    pool_.emplace(std::move(address));
    return;
  }
  if (!contains(address)) {
    pendingAddresses_.emplace(std::move(address));
  }
}

const QuicIPAddress& DefaultPoolMigrationAddressScheduler::next() {
  if (pool_.empty()) {
    throw QuicInternalException(
        "Attempt to iterate through an empty address pool",
        LocalErrorCode::INTERNAL_ERROR);
  }
  if (!iterating_) {
    // First call of a cycle, so merge the pending addresses, if any, and
    // restart the cycle, possibly from the current server address.
    iterating_ = true;
    pool_.merge(pendingAddresses_);
    iterator_ = pool_.cbegin();
    if (!currentServerAddress_.isAllZero()) {
      return currentServerAddress_;
    }
  }
  auto& address = *iterator_;
  ++iterator_;
  if (iterator_ == pool_.cend()) {
    iterating_ = false;
  }
  return address;
}

void DefaultPoolMigrationAddressScheduler::restart() {
  iterating_ = false;
  iterator_ = pool_.cend();
}

} // namespace quic
