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

std::string QuicServerMigrationNegotiator::supportedProtocolsToString() {
  if (supportedProtocols_.empty()) {
    return "none";
  }
  folly::fbstring output;
  for (const auto& protocol : supportedProtocols_) {
    if (output.empty()) {
      output = folly::fbstring(serverMigrationProtocolToString(protocol));
    } else {
      output = output + ", " +
          folly::fbstring(serverMigrationProtocolToString(protocol));
    }
  }
  return output.toStdString();
}

std::string QuicServerMigrationNegotiator::negotiatedProtocolsToString() {
  if (!negotiatedProtocols_ || negotiatedProtocols_->empty()) {
    return "none";
  }
  folly::fbstring output;
  for (const auto& protocol : negotiatedProtocols_.value()) {
    if (output.empty()) {
      output = folly::fbstring(serverMigrationProtocolToString(protocol));
    } else {
      output = output + ", " +
          folly::fbstring(serverMigrationProtocolToString(protocol));
    }
  }
  return output.toStdString();
}

} // namespace quic
