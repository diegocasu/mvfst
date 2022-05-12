/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicTransportBase.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/codec/QuicIPAddress.h>
#include <quic/common/TransportKnobs.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/server/handshake/ServerTransportParametersExtension.h>
#include <quic/server/state/ServerConnectionIdRejector.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicTransportStatsCallback.h>

#include <folly/io/async/AsyncTransportCertificate.h>

#include <fizz/record/Types.h>

namespace quic {

struct CipherInfo {
  TrafficKey trafficKey;
  fizz::CipherSuite cipherSuite;
  Buf packetProtectionKey;
};

class QuicServerTransport
    : public QuicTransportBase,
      public ServerHandshake::HandshakeCallback,
      public std::enable_shared_from_this<QuicServerTransport> {
 public:
  using Ptr = std::shared_ptr<QuicServerTransport>;
  using SourceIdentity = std::pair<folly::SocketAddress, ConnectionId>;

  class RoutingCallback {
   public:
    virtual ~RoutingCallback() = default;

    // Called when a connection id is available
    virtual void onConnectionIdAvailable(
        Ptr transport,
        ConnectionId id) noexcept = 0;

    // Called when a connecton id is bound and ip address should not
    // be used any more for routing.
    virtual void onConnectionIdBound(Ptr transport) noexcept = 0;

    // Called when the connection is finished and needs to be Unbound.
    virtual void onConnectionUnbound(
        QuicServerTransport* transport,
        const SourceIdentity& address,
        const std::vector<ConnectionIdData>& connectionIdData) noexcept = 0;
  };

  class HandshakeFinishedCallback {
   public:
    virtual ~HandshakeFinishedCallback() = default;

    virtual void onHandshakeFinished() noexcept = 0;

    virtual void onHandshakeUnfinished() noexcept = 0;
  };

  static QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      ConnectionSetupCallback* connSetupCb,
      ConnectionCallback* connStreamsCb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx,
      bool useConnectionEndWithErrorCallback = false);

  QuicServerTransport(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      ConnectionSetupCallback* connSetupCb,
      ConnectionCallback* connStreamsCb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx,
      std::unique_ptr<CryptoFactory> cryptoFactory = nullptr,
      bool useConnectionEndWithErrorCallback = false);

  // Testing only API:
  QuicServerTransport(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      ConnectionSetupCallback* connSetupCb,
      ConnectionCallback* connStreamsCb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx,
      std::unique_ptr<CryptoFactory> cryptoFactory,
      PacketNum startingPacketNum);

  ~QuicServerTransport() override;

  virtual void setRoutingCallback(RoutingCallback* callback) noexcept;

  virtual void setHandshakeFinishedCallback(
      HandshakeFinishedCallback* callback) noexcept;

  virtual void setOriginalPeerAddress(const folly::SocketAddress& addr);

  virtual void setServerConnectionIdParams(
      ServerConnectionIdParams params) noexcept;

  /**
   * Enables the server-side support for server migration.
   * It has no effect if called after the reception of the
   * first client packet.
   * @param supportedProtocols  the set of protocols that are supported
   *                            by the server. The set must be non-empty.
   * @return                    true if the server migration support has been
   *                            enabled, false otherwise.
   */
  bool allowServerMigration(
      const std::unordered_set<ServerMigrationProtocol>& supportedProtocols);

  /**
   * Adds an address to the set of possible migration addresses used in the
   * Pool of Addresses (PoA) server migration protocol. It has no effect if
   * called before allowServerMigration(), or when PoA has not been marked
   * as a supported protocol, or after the handshake has been completed.
   * If the migration protocol negotiation ends with PoA as one of the usable
   * protocols and this method has been called, the transport always uses
   * PoA as migration protocol, ignoring the other possible choices.
   * If the migration protocol negotiation ends with PoA not in the list of
   * usable protocols and this method has been called, the transport ignores
   * the PoA pool.
   * @param address  the Quic IP address to add to the PoA pool.
   *                 It must contain at least an address of the same family
   *                 of the one used in the transport.
   * @return         true if the address has been added to the PoA pool,
   *                 false otherwise.
   */
  bool addPoolMigrationAddress(const QuicIPAddress& address);

  /**
   * Notifies the transport that a server migration is imminent. Depending of
   * the chosen protocol, the transport notifies in turn the connected client
   * about the migration (e.g. sends a SERVER_MIGRATION frame). This method is
   * asynchronous, thus the transport is not necessarily ready to be migrated
   * when it returns: it is up to the caller to wait until the ready state is
   * reached. If setServerMigrationEventCallback() has been previously
   * called, the transport itself invokes onServerMigrationReady() to notify
   * this event; otherwise, the caller can only rely on the guarantees offered
   * by the specific migration protocol (e.g. if Pool of Addresses or Symmetric
   * are used, there is no need to communicate with the client, hence the
   * transport is ready to migrate as soon as this method ends).
   * If the transport cannot migrate, it closes the connection with the client,
   * possibly invoking onServerMigrationFailed() with the related error code.
   * It is an error to call this method before the handshake is completed, or
   * multiple times in a row before a migration is completed.
   * @param protocol          the migration protocol. It must be one of the
   *                          protocols negotiated with the client.
   * @param migrationAddress  the migration address to send to the client. It
   *                          must be set to folly::none if the given protocol
   *                          does not need a migration address in this phase,
   *                          like it happens with the Symmetric protocol.
   */
  virtual void onImminentServerMigration(
      const ServerMigrationProtocol& protocol,
      const folly::Optional<QuicIPAddress>& migrationAddress);

  /**
   * Notifies the transport to use a new socket due to a migration.
   * @param newSocket  the new socket.
   */
  void onNetworkSwitch(
      std::unique_ptr<folly::AsyncUDPSocket> newSocket) override;

  /**
   * Sets the callback to invoke when the server migration management
   * interface should be informed about the change of a client's state.
   * @param callback  the callback.
   * @return          true if the callback has been set, false otherwise.
   */
  bool setClientStateUpdateCallback(
      std::shared_ptr<ClientStateUpdateCallback> callback);

  /**
   * Sets the callback to invoke when an event related to server migration
   * occurs and should be notified to the server migration management interface.
   * @param callback  the callback.
   * @return          true if the callback has been set, false otherwise.
   */
  bool setServerMigrationEventCallback(
      std::shared_ptr<ServerMigrationEventCallback> callback);

  /**
   * Set callback for various transport stats (such as packet received, dropped
   * etc).
   */
  virtual void setTransportStatsCallback(
      QuicTransportStatsCallback* statsCallback) noexcept;

  /**
   * Set ConnectionIdAlgo implementation to encode and decode ConnectionId with
   * various info, such as routing related info.
   */
  virtual void setConnectionIdAlgo(ConnectionIdAlgo* connIdAlgo) noexcept;

  void setServerConnectionIdRejector(
      ServerConnectionIdRejector* connIdRejector) noexcept;

  virtual void setClientConnectionId(const ConnectionId& clientConnectionId);

  void setClientChosenDestConnectionId(const ConnectionId& serverCid);

  // From QuicTransportBase
  void onReadData(
      const folly::SocketAddress& peer,
      NetworkDataSingle&& networkData) override;
  void writeData() override;
  void closeTransport() override;
  void unbindConnection() override;
  bool hasWriteCipher() const override;
  std::shared_ptr<QuicTransportBase> sharedGuard() override;
  QuicConnectionStats getConnectionsStats() const override;

  const fizz::server::FizzServerContext& getCtx() {
    return *ctx_;
  }

  virtual void accept();

  virtual void setBufAccessor(BufAccessor* bufAccessor);

#ifdef CCP_ENABLED
  /*
   * This function must be called with an initialized ccp_datapath (via
   * libccp:ccp_init) before starting any connections using the CCP congestion
   * control algorithm. See further notes on this struct in the header file.
   */
  void setCcpDatapath(struct ccp_datapath* datapath);
#endif

  const std::shared_ptr<const folly::AsyncTransportCertificate>
  getPeerCertificate() const override;

  virtual CipherInfo getOneRttCipherInfo() const;

  /**
   * Returns the original connection ID derived by the transport, namely the
   * one used to finalize the handshake, if the handshake has been finished.
   */
  virtual folly::Optional<ConnectionId> getOriginalConnectionId();

 protected:
  // From ServerHandshake::HandshakeCallback
  virtual void onCryptoEventAvailable() noexcept override;

  void onTransportKnobs(Buf knobBlob) override;

  void handleTransportKnobParams(const TransportKnobParams& params);

  // Made it protected for testing purpose
  void registerTransportKnobParamHandler(
      uint64_t paramId,
      std::function<void(QuicServerTransport*, uint64_t)>&& handler);

 private:
  void processPendingData(bool async);
  void maybeNotifyTransportReady();
  void maybeNotifyConnectionIdBound();
  void maybeWriteNewSessionTicket();
  void maybeIssueConnectionIds();
  void maybeNotifyHandshakeFinished();
  bool hasReadCipher() const;
  void maybeStartD6DProbing();
  void registerAllTransportKnobParamHandlers();
  void maybeSendPoolMigrationAddresses();

  void handleExplicitImminentServerMigration(
      const folly::Optional<QuicIPAddress>& migrationAddress);
  void handlePoolOfAddressesImminentServerMigration(
      const folly::Optional<QuicIPAddress>& migrationAddress);
  void handleSymmetricImminentServerMigration(
      const folly::Optional<QuicIPAddress>& migrationAddress);
  void handleSynchronizedSymmetricImminentServerMigration(
      const folly::Optional<QuicIPAddress>& migrationAddress);

 private:
  RoutingCallback* routingCb_{nullptr};
  HandshakeFinishedCallback* handshakeFinishedCb_{nullptr};
  std::shared_ptr<const fizz::server::FizzServerContext> ctx_;
  bool notifiedRouting_{false};
  bool notifiedConnIdBound_{false};
  bool newSessionTicketWritten_{false};
  bool connectionIdsIssued_{false};
  QuicServerConnectionState* serverConn_;
  std::unordered_map<
      uint64_t,
      std::function<void(QuicServerTransport*, uint64_t)>>
      transportKnobParamHandlers_;
};
} // namespace quic
