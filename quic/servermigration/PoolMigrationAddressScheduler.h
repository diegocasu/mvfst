#pragma once

#include <quic/codec/QuicIPAddress.h>

namespace quic {

/**
 * Interface to represent a scheduler that cycles through addresses received
 * from POOL_MIGRATION_ADDRESS frames. A scheduler is said to be empty if it
 * does not contain addresses.
 */
class PoolMigrationAddressScheduler {
 public:
  virtual ~PoolMigrationAddressScheduler() = default;

  /**
   * Inserts a new address in the scheduler, if not already present.
   * It can be called even if a cycle is on-going, but the guarantees of this
   * operation depend on the particular implementation (the address could be
   * available in the current cycle, or starting from the next one, etc.).
   * @param address  the address. It is ignored if all-zero.
   */
  virtual void insert(QuicIPAddress address) = 0;

  /**
   * Returns the next address in the cycle, advancing it.
   * It throws a QuicInternalException exception if the scheduler is empty.
   * @return  the next address in the cycle.
   */
  virtual const QuicIPAddress& next() = 0;

  /**
   * Returns true if the scheduler contains the given address.
   * It considers only addresses added with insert().
   * @param address  the address.
   * @return         true if the scheduler contains the given address,
   *                 false otherwise.
   */
  virtual bool contains(const QuicIPAddress& address) = 0;

  /**
   * Restarts the cycle from the beginning.
   */
  virtual void restart() = 0;

  /**
   * Sets the current address of the server.
   * @param address  the current address of the server.
   *                 If all-zero, it resets the address.
   */
  virtual void setCurrentServerAddress(QuicIPAddress address) = 0;

  /**
   * Returns the current address of the server. If the latter has not been
   * set, it returns an all-zero QuicIPAddress.
   * @return  the current address of the server, if set;
   *          an all-zero QuicIPAddress otherwise.
   */
  virtual const QuicIPAddress& getCurrentServerAddress() = 0;
};

} // namespace quic
