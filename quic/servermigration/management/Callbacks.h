#pragma once

#include <folly/SocketAddress.h>
#include <quic/QuicConstants.h>
#include <quic/codec/QuicConnectionId.h>

namespace quic {

/**
 * Callbacks invoked when the state of a client changes in a way that should
 * be notified to the server migration management interface.
 * The callbacks can be invoked by multiple threads (workers) concurrently,
 * thus their implementations must be thread-safe. Moreover, since they are
 * executed synchronously when called, their operations must not be blocking
 * or heavyweight to avoid freezing the worker: if such operations are required,
 * they must be delegated to a separate dedicated thread.
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
  virtual void onMigrationDetected(
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

} // namespace quic
