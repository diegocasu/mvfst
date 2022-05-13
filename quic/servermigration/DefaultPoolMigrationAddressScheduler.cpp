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
    // First call of a cycle, so try to return the server address.
    iterating_ = true;
    if (!currentServerAddress_.isAllZero()) {
      return currentServerAddress_;
    }
  }
  if (iterator_ == pool_.cend()) {
    // The last iteration ended the cycle, so merge the pending addresses,
    // if any, and restart the cycle from the first address of the pool.
    pool_.merge(pendingAddresses_);
    iterator_ = pool_.begin();
  }
  auto& address = *iterator_;
  ++iterator_;
  if (iterator_ == pool_.end()) {
    iterating_ = false;
  }
  return address;
}

void DefaultPoolMigrationAddressScheduler::restart() {
  iterating_ = false;
  iterator_ = pool_.cend();
}

} // namespace quic
