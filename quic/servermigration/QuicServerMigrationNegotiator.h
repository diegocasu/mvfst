#pragma once

#include <folly/Optional.h>
#include <quic/QuicConstants.h>
#include <quic/handshake/TransportParameters.h>

namespace quic {

/**
 * Base class for the negotiation of the server migration protocol.
 * It is intended to be sub-classed for each endpoint (client/server).
 */
class QuicServerMigrationNegotiator {
 protected:
  std::unordered_set<ServerMigrationProtocol> supportedProtocols_;
  folly::Optional<std::unordered_set<ServerMigrationProtocol>>
      negotiatedProtocols_;

 public:
  /**
   * Creates a new negotiator.
   * @param supportedProtocols  the list of protocols supported by the endpoint.
   *                            It must be non empty.
   */
  explicit QuicServerMigrationNegotiator(
      std::unordered_set<ServerMigrationProtocol> supportedProtocols);

  virtual ~QuicServerMigrationNegotiator() = default;

  QuicServerMigrationNegotiator(QuicServerMigrationNegotiator&&) = default;
  QuicServerMigrationNegotiator(const QuicServerMigrationNegotiator&) = default;
  QuicServerMigrationNegotiator& operator=(
      const QuicServerMigrationNegotiator&) = default;
  QuicServerMigrationNegotiator& operator=(QuicServerMigrationNegotiator&&) =
      default;

  /**
   * Returns the list of negotiated protocols. If the negotiation has not
   * already been completed, it returns a null value. Otherwise, it returns
   * the (possibly empty) list of agreed protocols.
   * @return  the list of negotiated protocols.
   */
  const folly::Optional<std::unordered_set<ServerMigrationProtocol>>&
  getNegotiatedProtocols() const;

  const std::unordered_set<ServerMigrationProtocol>& getSupportedProtocols()
      const;

  std::string supportedProtocolsToString();

  std::string negotiatedProtocolsToString();

  /**
   * Returns the encoded value of the server_migration_suite transport
   * parameter to send to the peer. This method is called before the
   * transport parameters are passed to the TLS layer. Depending on the role
   * of the endpoint, this method could be invoked before
   * onMigrationSuiteReceived() (client) or after (server).
   * @return  the encoded value of the server_migration_suite
   *          transport parameter to send to the peer.
   */
  virtual TransportParameter onTransportParametersEncoding() = 0;

  /**
   * Called after the transport parameters received from the peer have been
   * parsed by the TLS layer. Depending on the role of the endpoint, this method
   * could be invoked before onTransportParametersEncoding() (server)
   * or after (client).
   * @param migrationSuite  the encoded value of the server_migration_suite
   *                        transport parameter received from the peer.
   */
  virtual void onMigrationSuiteReceived(TransportParameter migrationSuite) = 0;
};

} // namespace quic
