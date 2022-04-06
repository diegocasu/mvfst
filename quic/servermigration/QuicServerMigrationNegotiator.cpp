#include "QuicServerMigrationNegotiator.h"

namespace quic {

QuicServerMigrationNegotiator::QuicServerMigrationNegotiator(
    std::vector<ServerMigrationProtocol> supportedProtocols)
    : supportedProtocols_(std::move(supportedProtocols)) {
  if (supportedProtocols_.empty()) {
    throw QuicInternalException(
        "No protocols passed to the server migration protocol negotiator",
        LocalErrorCode::INTERNAL_ERROR);
  }
}

const folly::Optional<std::vector<ServerMigrationProtocol>>&
QuicServerMigrationNegotiator::getNegotiatedProtocols() {
  return negotiatedProtocols_;
}

const std::vector<ServerMigrationProtocol>&
QuicServerMigrationNegotiator::getSupportedProtocols() {
  return supportedProtocols_;
}

} // namespace quic
