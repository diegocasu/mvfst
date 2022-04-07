#include "QuicServerMigrationNegotiatorServer.h"

namespace quic {

QuicServerMigrationNegotiatorServer::QuicServerMigrationNegotiatorServer(
    std::unordered_set<ServerMigrationProtocol> supportedProtocols)
    : QuicServerMigrationNegotiator(std::move(supportedProtocols)) {}

void QuicServerMigrationNegotiatorServer::onMigrationSuiteReceived(
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
  if (migrationSuiteValue == 0) {
    throw QuicTransportException(
        "No protocols in server_migration_suite",
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }

  std::unordered_set<ServerMigrationProtocol> candidateNegotiatedProtocols;
  for (uint64_t mask = 0x1;
       mask <= static_cast<uint64_t>(ServerMigrationProtocol::MAX);
       mask = mask << 1) {
    uint64_t maskedSuite = migrationSuiteValue & mask;
    if (maskedSuite == 0) {
      continue;
    }

    auto protocol = static_cast<ServerMigrationProtocol>(mask);
    if (supportedProtocols_.count(protocol)) {
      candidateNegotiatedProtocols.insert(protocol);
    }
  }

  negotiatedProtocols_ = std::move(candidateNegotiatedProtocols);
}

TransportParameter
QuicServerMigrationNegotiatorServer::onTransportParametersEncoding() {
  if (!negotiatedProtocols_) {
    throw QuicTransportException(
        "Cannot encode server_migration_suite without a successful negotiation",
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }

  uint64_t accumulator = 0;

  // Set a single bit in the accumulator for each negotiated protocol.
  // The OR works due to the underlying representation
  // of ServerMigrationProtocol.
  for (const auto& protocol : negotiatedProtocols_.value()) {
    accumulator |= static_cast<uint64_t>(protocol);
  }

  CustomIntegralTransportParameter parameter(
      static_cast<uint64_t>(TransportParameterId::server_migration_suite),
      accumulator);

  return parameter.encode();
}

} // namespace quic
