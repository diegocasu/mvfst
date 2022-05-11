#pragma once

namespace quic {

/**
 * Callback invoked when a probe timeout is triggered.
 */
class QuicProbeTimeoutCallback {
 public:
  virtual ~QuicProbeTimeoutCallback() = default;

  /**
   * Invoked when a probe timeout is triggered.
   */
  virtual void onProbeTimeout() = 0;
};

} // namespace quic