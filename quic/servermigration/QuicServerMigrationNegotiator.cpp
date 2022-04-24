#include "QuicServerMigrationNegotiator.h"

namespace quic {

QuicServerMigrationNegotiator::QuicServerMigrationNegotiator(
    std::unordered_set<ServerMigrationProtocol> supportedProtocols)
    : supportedProtocols_(std::move(supportedProtocols)) {
  if (supportedProtocols_.empty()) {
    throw QuicInternalException(
        "No protocols passed to the server migration protocol negotiator",
        LocalErrorCode::INTERNAL_ERROR);
  }
}

const folly::Optional<std::unordered_set<ServerMigrationProtocol>>&
QuicServerMigrationNegotiator::getNegotiatedProtocols() const {
  return negotiatedProtocols_;
}

const std::unordered_set<ServerMigrationProtocol>&
QuicServerMigrationNegotiator::getSupportedProtocols() const {
  return supportedProtocols_;
}

} // namespace quic
