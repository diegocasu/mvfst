#pragma once

#include <folly/SocketAddress.h>
#include <quic/QuicConstants.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/Types.h>

namespace quic {

/**
 * Callbacks invoked when the state of a client changes.
 * They should be implemented only on the server side.
 * The callbacks can be invoked by multiple threads (workers) concurrently,
 * thus their implementations must be thread-safe. Moreover, since they are
 * executed synchronously when called, their operations must not be blocking
 * or heavyweight to avoid freezing the worker: if such operations are required,
 * they must be delegated to a separate dedicated thread.
 * The server connection IDs that are passed as arguments to the callbacks are
 * the original connection IDs derived by the associated transports, namely the
 * ones used to finalize the handshake. They can be used to correctly identify
 * the transports when notifying an imminent server migration.
 */
class ClientStateUpdateCallback {
 public:
  virtual ~ClientStateUpdateCallback() = default;

  /**
   * Called when a new client completes the handshake with the server.
   * @param clientAddress        the initial IP address and port of the client.
   * @param serverConnectionId   the CID identifying the instance of
   *                             QuicServerTransport that manages the
   *                             connection with the client.
   * @param negotiatedProtocols  the server migration protocols negotiated
   *                             during the handshake, if any.
   */
  virtual void onHandshakeFinished(
      folly::SocketAddress clientAddress,
      ConnectionId serverConnectionId,
      folly::Optional<std::unordered_set<ServerMigrationProtocol>>
          negotiatedProtocols) noexcept = 0;

  /**
   * Called when a client migration is detected.
   * @param serverConnectionId  the CID identifying the instance of
   *                            QuicServerTransport that manages the
   *                            connection with the client.
   * @param newClientAddress    the new IP address and port of the client.
   */
  virtual void onClientMigrationDetected(
      ConnectionId serverConnectionId,
      folly::SocketAddress newClientAddress) noexcept = 0;

  /**
   * Called when the connection with a client is being closed.
   * @param serverConnectionId  the connection ID of the QuicServerTransport
   *                            instance managing the connection with
   *                            the client. It matches the one provided with
   *                            onHandshakeFinished().
   */
  virtual void onConnectionClose(ConnectionId serverConnectionId) noexcept = 0;
};

/**
 * Callbacks invoked when an event related to server migration occurs.
 * For each of them, it is specified if it should be implemented on the
 * client side or on the server side.
 * The callbacks can be invoked by multiple threads (workers) concurrently,
 * if called on the server-side, thus their implementations must be thread-safe.
 * Moreover, since they are executed synchronously when called, their operations
 * must not be blocking or heavyweight to avoid freezing the worker: if such
 * operations are required, they must be delegated to a separate dedicated
 * thread.
 * The server connection IDs that are passed as arguments to the callbacks are
 * the original connection IDs derived by the associated transports, namely the
 * ones used to finalize the handshake. They can be used to correctly identify
 * the transports when notifying an imminent server migration.
 */
class ServerMigrationEventCallback {
 public:
  virtual ~ServerMigrationEventCallback() = default;

  /**
   * Called when a POOL_MIGRATION_ADDRESS frame is received.
   * It is not called if the frame is a duplicate, or
   * causes a protocol violation.
   * It should be implemented only on the client side.
   * @param frame  the received POOL_MIGRATION_ADDRESS frame.
   */
  virtual void onPoolMigrationAddressReceived(
      PoolMigrationAddressFrame /*frame*/) noexcept {};

  /**
   * Called when an acknowledgement for a previously sent
   * POOL_MIGRATION_ADDRESS frame is received.
   * It is not called if the acknowledgement is a duplicate.
   * It should be implemented only on the server side.
   * @param serverConnectionId  the connection ID of the QuicServerTransport
   *                            instance managing the connection.
   * @param frame               the acknowledged POOL_MIGRATION_ADDRESS frame.
   */
  virtual void onPoolMigrationAddressAckReceived(
      ConnectionId /*serverConnectionId*/,
      PoolMigrationAddressFrame /*frame*/) noexcept {};

  /**
   * Called when a SERVER_MIGRATION frame is received.
   * It is not called if the frame is a duplicate, or
   * causes a protocol violation.
   * It should be implemented only on the client side.
   * @param frame  the received SERVER_MIGRATION frame.
   */
  virtual void onServerMigrationReceived(
      ServerMigrationFrame /*frame*/) noexcept {};

  /**
   * Called when an acknowledgement for a previously sent
   * SERVER_MIGRATION frame is received.
   * It is not called if the acknowledgement is a duplicate.
   * It should be implemented only on the server side.
   * @param serverConnectionId  the connection ID of the QuicServerTransport
   *                            instance managing the connection.
   * @param frame               the acknowledged SERVER_MIGRATION frame.
   */
  virtual void onServerMigrationAckReceived(
      ConnectionId /*serverConnectionId*/,
      ServerMigrationFrame /*frame*/) noexcept {};

  /**
   * Called when a client starts probing a new server address sending a PING
   * frame. For the Explicit protocol, it is invoked only once at the beginning
   * of the probing phase; for the Pool of Addresses protocol, it is invoked
   * every time a different address of the pool is involved in the probing.
   * @param protocol        the server migration protocol.
   * @param probingAddress  the address that is being probed.
   */
  virtual void onServerMigrationProbingStarted(
      ServerMigrationProtocol /*protocol*/,
      folly::SocketAddress /*probingAddress*/) noexcept {};

  /**
   * Called when the invocation of onImminentServerMigration() on a
   * transport fails. It should be implemented only on the server side.
   * @param serverConnectionId  the connection ID of the QuicServerTransport
   *                            instance.
   * @param error               the error.
   */
  virtual void onServerMigrationFailed(
      ConnectionId /*serverConnectionId*/,
      ServerMigrationError /*error*/) noexcept {}

  /**
   * Called when the invocation of onImminentServerMigration() on a
   * transport succeeds. It should be implemented only on the server side.
   * @param serverConnectionId  the connection ID of the QuicServerTransport
   *                            instance.
   */
  virtual void onServerMigrationReady(
      ConnectionId /*serverConnectionId*/) noexcept {}
};

} // namespace quic
