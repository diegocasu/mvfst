#pragma once

#include <quic/codec/Types.h>

namespace quic {

/**
 * Callbacks invoked when an event related to packet loss happens.
 */
class QuicPacketLossCallback {
 public:
  virtual ~QuicPacketLossCallback() = default;

  /**
   * Invoked when a packet is marked as lost.
   * @param packetNumber  the packet number of the packet marked as lost.
   */
  virtual void onPacketMarkedLost(PacketNum packetNumber) = 0;
};

} // namespace quic