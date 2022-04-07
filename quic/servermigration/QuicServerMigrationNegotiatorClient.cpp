#include "QuicServerMigrationNegotiatorClient.h"

namespace quic {

QuicServerMigrationNegotiatorClient::QuicServerMigrationNegotiatorClient(
    std::unordered_set<ServerMigrationProtocol> supportedProtocols)
    : QuicServerMigrationNegotiator(std::move(supportedProtocols)) {}

TransportParameter
QuicServerMigrationNegotiatorClient::onTransportParametersEncoding() {
  uint64_t accumulator = 0;

  // Set a single bit in the accumulator for each supported protocol.
  // The OR works due to the underlying representation
  // of ServerMigrationProtocol.
  for (const auto& protocol : supportedProtocols_) {
    accumulator |= static_cast<uint64_t>(protocol);
  }

  CustomIntegralTransportParameter parameter(
      static_cast<uint64_t>(TransportParameterId::server_migration_suite),
      accumulator);

  return parameter.encode();
}

void QuicServerMigrationNegotiatorClient::onMigrationSuiteReceived(
    TransportParameter migrationSuite) {
  if (migrationSuite.parameter !=
      TransportParameterId::server_migration_suite) {
    throw QuicTransportException(
        folly::to<std::string>(
            "Wrong transport parameter passed to negotiator: ",
            migrationSuite.parameter),
        TransportErrorCode::INTERNAL_ERROR);
  }

  auto cursor = folly::io::Cursor(migrationSuite.value.get());
  auto decodedMigrationSuite = decodeQuicInteger(cursor);
  if (!decodedMigrationSuite) {
    throw QuicTransportException(
        "Failed to decode server_migration_suite",
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }

  uint64_t migrationSuiteValue = decodedMigrationSuite.value().first;

  // The suite cannot contain bits identifying an unknown protocol.
  uint64_t unknownProtocolThreshold =
      static_cast<uint64_t>(ServerMigrationProtocol::MAX) |
      (static_cast<uint64_t>(ServerMigrationProtocol::MAX) - 1);

  if (migrationSuiteValue > unknownProtocolThreshold) {
    throw QuicTransportException(
        "Unknown protocol in server_migration_suite",
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }

  std::unordered_set<ServerMigrationProtocol> candidateNegotiatedProtocols;

  if (migrationSuiteValue == 0) {
    negotiatedProtocols_ = std::move(candidateNegotiatedProtocols);
    return;
  }

  for (uint64_t mask = 0x1;
       mask <= static_cast<uint64_t>(ServerMigrationProtocol::MAX);
       mask = mask << 1) {
    uint64_t maskedSuite = migrationSuiteValue & mask;
    if (maskedSuite == 0) {
      continue;
    }

    auto protocol = static_cast<ServerMigrationProtocol>(mask);
    if (!supportedProtocols_.count(protocol)) {
      throw QuicTransportException(
          "Unsupported protocol in server_migration_suite",
          TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
    }

    candidateNegotiatedProtocols.insert(protocol);
  }

  negotiatedProtocols_ = std::move(candidateNegotiatedProtocols);
}

} // namespace quic
