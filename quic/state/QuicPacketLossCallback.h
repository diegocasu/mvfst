#pragma once

#include <quic/codec/Types.h>

namespace quic {

/**
 * Callbacks invoked when an event related to packet loss happens.
 * Note that multiple callbacks can be invoked one after the other due
 * to the same packet loss event.
 */
class QuicPacketLossCallback {
 public:
  virtual ~QuicPacketLossCallback() = default;

  /**
   * Invoked when a packet is marked as lost.
   * @param packetNumber  the packet number of the packet marked as lost.
   */
  virtual void onPacketMarkedLost(PacketNum packetNumber) = 0;

  /**
   * Invoked when a PING frame is marked as lost.
   * @param packetNumber  the packet number of the packet containing the
   *                      PING frame marked as lost.
   */
  virtual void onPingFrameMarkedLost(PacketNum packetNumber) = 0;
};

} // namespace quic