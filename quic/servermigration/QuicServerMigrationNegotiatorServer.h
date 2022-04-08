#pragma once

#include <quic/servermigration/QuicServerMigrationNegotiator.h>

namespace quic {

class QuicServerMigrationNegotiatorServer
    : public QuicServerMigrationNegotiator {
 public:
  /**
   * Creates a new negotiator.
   * @param supportedProtocols  the list of protocols supported by the endpoint.
   *                            It must be non empty.
   */
  explicit QuicServerMigrationNegotiatorServer(
      std::unordered_set<ServerMigrationProtocol> supportedProtocols);

  ~QuicServerMigrationNegotiatorServer() override = default;

  QuicServerMigrationNegotiatorServer(QuicServerMigrationNegotiatorServer&&) =
      default;
  QuicServerMigrationNegotiatorServer(
      const QuicServerMigrationNegotiatorServer&) = default;
  QuicServerMigrationNegotiatorServer& operator=(
      const QuicServerMigrationNegotiatorServer&) = default;
  QuicServerMigrationNegotiatorServer& operator=(
      QuicServerMigrationNegotiatorServer&&) = default;

  TransportParameter onTransportParametersEncoding() override;
  void onMigrationSuiteReceived(TransportParameter migrationSuite) override;
};

} // namespace quic
