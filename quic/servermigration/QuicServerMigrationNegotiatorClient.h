#pragma once

#include <quic/servermigration/QuicServerMigrationNegotiator.h>

namespace quic {

class QuicServerMigrationNegotiatorClient
    : public QuicServerMigrationNegotiator {
 public:
  /**
   * Creates a new negotiator.
   * @param supportedProtocols  the list of protocols supported by the endpoint.
   *                            It must be non empty.
   */
  explicit QuicServerMigrationNegotiatorClient(
      std::unordered_set<ServerMigrationProtocol> supportedProtocols);

  ~QuicServerMigrationNegotiatorClient() override = default;

  TransportParameter onTransportParametersEncoding() override;
  void onMigrationSuiteReceived(TransportParameter migrationSuite) override;
};

} // namespace quic