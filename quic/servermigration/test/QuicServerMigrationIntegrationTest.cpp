#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/server/QuicServer.h>
#include <quic/servermigration/test/Mocks.h>

using namespace testing;

namespace quic {
namespace test {

class QuicServerMigrationIntegrationTestClient
    : public QuicSocket::ConnectionSetupCallback,
      public QuicSocket::ConnectionCallback,
      public QuicSocket::ReadCallback,
      public QuicSocket::WriteCallback {
 private:
  void sendMessage(quic::StreamId id, BufQueue& data) {
    auto message = data.move();
    auto res = transport->writeChain(id, message->clone(), true);
    if (res.hasError()) {
      LOG(ERROR) << "writeChain error=" << uint32_t(res.error());
    } else {
      auto str = message->moveToFbString().toStdString();
      LOG(INFO) << "Wrote \"" << str << "\""
                << ", len=" << str.size() << " on stream=" << id;
      pendingOutput_.erase(id);
    }
  }

 public:
  QuicServerMigrationIntegrationTestClient(
      std::string clientHost,
      uint16_t clientPort,
      std::string serverHost,
      uint16_t serverPort,
      std::unordered_set<ServerMigrationProtocol> migrationProtocols,
      std::shared_ptr<ServerMigrationEventCallback>
          serverMigrationEventCallback = nullptr)
      : clientHost(std::move(clientHost)),
        clientPort(clientPort),
        serverHost(std::move(serverHost)),
        serverPort(serverPort),
        migrationProtocols(std::move(migrationProtocols)),
        serverMigrationEventCallback(std::move(serverMigrationEventCallback)) {}

  ~QuicServerMigrationIntegrationTestClient() = default;

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "New bidirectional stream=" << id;
    transport->setReadCallback(id, this);
  }

  void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "New unidirectional stream=" << id;
    transport->setReadCallback(id, this);
  }

  void onStopSending(
      quic::StreamId id,
      quic::ApplicationErrorCode error) noexcept override {
    LOG(INFO) << "Received StopSending on stream=" << id << " error=" << error;
  }

  void onConnectionEnd() noexcept override {
    LOG(INFO) << "Connection end";
  }

  void onConnectionSetupError(QuicError error) noexcept override {
    onConnectionError(std::move(error));
  }

  void onConnectionError(QuicError error) noexcept override {
    LOG(ERROR) << "Connection error: " << toString(error.code)
               << "; errStr=" << error.message;
    if (connectionErrorTestPredicate) {
      connectionErrorTestPredicate(error);
    }
    startDone_.post();
  }

  void onReplaySafe() noexcept override {
    startDone_.post();
  }

  void readAvailable(quic::StreamId streamId) noexcept override {
    LOG(INFO) << "Read available for stream=" << streamId;

    auto readData = transport->read(streamId, 0);
    if (readData.hasError()) {
      LOG(ERROR) << "Failed read from stream=" << streamId
                 << ", error=" << (uint32_t)readData.error();
    }

    auto copy = readData->first->clone();
    if (recvOffsets_.find(streamId) == recvOffsets_.end()) {
      recvOffsets_[streamId] = copy->length();
    } else {
      recvOffsets_[streamId] += copy->length();
    }
    LOG(INFO) << "Received data=" << copy->moveToFbString().toStdString()
              << " on stream=" << streamId;
    messageReceived.post();
  }

  void readError(quic::StreamId streamId, QuicError error) noexcept override {
    LOG(ERROR) << "Failed read from stream=" << streamId
               << ", error=" << toString(error);
    transport->resetStream(
        streamId, static_cast<uint16_t>(LocalErrorCode::APP_ERROR));
    messageReceived.post();
  }

  void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
      override {
    LOG(INFO) << "Stream is write ready with maxToSend=" << maxToSend;
    sendMessage(id, pendingOutput_[id]);
  }

  void onStreamWriteError(quic::StreamId id, QuicError error) noexcept
      override {
    LOG(ERROR) << "Stream write error on stream=" << id
               << " error=" << toString(error);
  }

  void setKeyLoggerConfig(
      const std::string& fileName,
      QuicKeyLogWriter::WriteMode writeMode) noexcept {
    QuicKeyLogWriter::Config config;
    config.fileName = fileName;
    config.flushPolicy = QuicKeyLogWriter::FlushPolicy::IMMEDIATELY;
    config.writeMode = writeMode;
    keyLoggerConfig_ = std::move(config);
  }

  void start() {
    auto evb = networkThread.getEventBase();

    evb->runInEventBaseThreadAndWait([&] {
      folly::SocketAddress clientAddress(clientHost.c_str(), clientPort);
      auto sock = std::make_unique<folly::AsyncUDPSocket>(evb);
      sock->bind(clientAddress);

      std::shared_ptr<FizzClientQuicHandshakeContext> fizzClientContext;
      if (keyLoggerConfig_) {
        LOG(INFO) << "Setting key logger configuration";
        fizzClientContext =
            FizzClientQuicHandshakeContext::Builder()
                .setCertificateVerifier(test::createTestCertificateVerifier())
                .enableKeyLogging(keyLoggerConfig_.value())
                .build();
      } else {
        LOG(INFO) << "Ignoring key logger configuration";
        fizzClientContext =
            FizzClientQuicHandshakeContext::Builder()
                .setCertificateVerifier(test::createTestCertificateVerifier())
                .build();
      }

      transport = std::make_shared<quic::QuicClientTransport>(
          evb, std::move(sock), std::move(fizzClientContext), 8);

      folly::SocketAddress serverAddress(serverHost.c_str(), serverPort);
      transport->addNewPeerAddress(serverAddress);

      TransportSettings settings;
      settings.maxNumPTOs = 50;
      settings.selfActiveConnectionIdLimit = 10;
      transport->setTransportSettings(settings);

      if (!migrationProtocols.empty()) {
        transport->allowServerMigration(migrationProtocols);
      } else {
        LOG(INFO)
            << "Disabling support for server migration: no protocols available";
      }

      if (serverMigrationEventCallback) {
        transport->setServerMigrationEventCallback(
            serverMigrationEventCallback);
      } else {
        LOG(INFO)
            << "Disabling support for server migration event updates: no callback available";
      }

      transport->start(this, this);
    });
  }

  void close() {
    auto evb = networkThread.getEventBase();
    evb->runInEventBaseThreadAndWait([&] { transport->closeNow(folly::none); });
  }

  void send(const std::string& message) {
    CHECK(!message.empty());
    auto evb = networkThread.getEventBase();
    evb->runInEventBaseThreadAndWait([=] {
      auto streamId = transport->createBidirectionalStream().value();
      transport->setReadCallback(streamId, this);
      pendingOutput_[streamId].append(folly::IOBuf::copyBuffer(message));
      sendMessage(streamId, pendingOutput_[streamId]);
    });
  }

  void setConnectionErrorTestPredicate(
      std::function<void(QuicError)> predicate) {
    connectionErrorTestPredicate = std::move(predicate);
  }

  std::string clientHost;
  uint16_t clientPort;
  std::string serverHost;
  uint16_t serverPort;
  std::shared_ptr<quic::QuicClientTransport> transport;
  folly::ScopedEventBaseThread networkThread;
  std::unordered_set<ServerMigrationProtocol> migrationProtocols;
  std::shared_ptr<ServerMigrationEventCallback> serverMigrationEventCallback;
  folly::Optional<QuicKeyLogWriter::Config> keyLoggerConfig_;

  // Synchronization variables.
  folly::fibers::Baton startDone_;
  folly::fibers::Baton messageReceived;

  // Maps used to read/write messages.
  std::map<quic::StreamId, BufQueue> pendingOutput_;
  std::map<quic::StreamId, uint64_t> recvOffsets_;

  // Test predicates.
  std::function<void(QuicError)> connectionErrorTestPredicate;
};

class QuicServerMigrationIntegrationTestServer {
 public:
  using StreamData = std::pair<BufQueue, bool>;

  class MessageHandler : public QuicSocket::ConnectionSetupCallback,
                         public QuicSocket::ConnectionCallback,
                         public QuicSocket::ReadCallback,
                         public QuicSocket::WriteCallback {
   public:
    MessageHandler(folly::EventBase* evb) : evb(evb){};
    ~MessageHandler() = default;

    void setQuicSocket(std::shared_ptr<quic::QuicSocket> socket) {
      sock = socket;
    }

    void onNewBidirectionalStream(quic::StreamId id) noexcept override {
      LOG(INFO) << "New bidirectional stream=" << id;
      sock->setReadCallback(id, this);
    }

    void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
      LOG(INFO) << "New unidirectional stream=" << id;
      sock->setReadCallback(id, this);
    }

    void onStopSending(
        quic::StreamId id,
        quic::ApplicationErrorCode error) noexcept override {
      LOG(INFO) << "Received StopSending on stream=" << id
                << " error=" << error;
    }

    void onConnectionEnd() noexcept override {
      LOG(INFO) << "Connection end";
    }

    void onConnectionSetupError(QuicError error) noexcept override {
      onConnectionError(std::move(error));
    }

    void onConnectionError(QuicError error) noexcept override {
      LOG(ERROR) << "Connection error: " << toString(error.code)
                 << "; errStr=" << error.message;
      EXPECT_NE(error.code.type(), QuicErrorCode::Type::TransportErrorCode);
      if (error.code.type() == QuicErrorCode::Type::LocalErrorCode) {
        auto errorCode = *error.code.asLocalErrorCode();
        EXPECT_TRUE(
            errorCode == LocalErrorCode::SHUTTING_DOWN ||
            errorCode == LocalErrorCode::SERVER_MIGRATED);
      }
    }

    void readAvailable(quic::StreamId id) noexcept override {
      LOG(INFO) << "Read available for stream=" << id;

      auto res = sock->read(id, 0);
      if (res.hasError()) {
        LOG(ERROR) << "Failed read from stream=" << id
                   << ", error=" << (uint32_t)res.error();
        return;
      }

      if (input_.find(id) == input_.end()) {
        input_.emplace(id, std::make_pair(BufQueue(), false));
      }

      quic::Buf data = std::move(res.value().first);
      bool eof = res.value().second;
      auto dataLen = (data ? data->computeChainDataLength() : 0);
      LOG(INFO) << "Received len=" << dataLen << " eof=" << uint32_t(eof)
                << " total=" << input_[id].first.chainLength() + dataLen
                << " data="
                << ((data) ? data->clone()->moveToFbString().toStdString()
                           : std::string());
      input_[id].first.append(std::move(data));
      input_[id].second = eof;
      if (eof) {
        echo(id, input_[id]);
      }
    }

    void readError(quic::StreamId id, QuicError error) noexcept override {
      LOG(ERROR) << "Read error on stream=" << id
                 << " error=" << toString(error);
      sock->resetStream(id, static_cast<uint16_t>(LocalErrorCode::APP_ERROR));
    }

    void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
        override {
      LOG(INFO) << "Stream is write ready with maxToSend=" << maxToSend;
      echo(id, input_[id]);
    }

    void onStreamWriteError(quic::StreamId id, QuicError error) noexcept
        override {
      LOG(ERROR) << "Stream write error on stream=" << id
                 << " error=" << toString(error);
    }

    void echo(quic::StreamId id, StreamData& data) {
      if (!data.second) {
        // Only echo when eof is present
        return;
      }

      auto echoedData = folly::IOBuf::copyBuffer("echo ");
      echoedData->prependChain(data.first.move());
      auto res = sock->writeChain(id, std::move(echoedData), true, nullptr);
      if (res.hasError()) {
        LOG(ERROR) << "Write error=" << toString(res.error());
      } else {
        // Echo is done, clear EOF
        data.second = false;
      }
    }

    std::shared_ptr<quic::QuicSocket> sock;
    folly::EventBase* evb;

   private:
    std::map<quic::StreamId, StreamData> input_;
  };

  class ServerTransportFactory : public QuicServerTransportFactory {
   public:
    ServerTransportFactory(
        std::unordered_set<ServerMigrationProtocol> migrationProtocols,
        std::unordered_set<QuicIPAddress, QuicIPAddressHash>
            poolMigrationAddresses,
        std::shared_ptr<ClientStateUpdateCallback> clientStateCallback,
        std::shared_ptr<ServerMigrationEventCallback>
            serverMigrationEventCallback)
        : migrationProtocols(std::move(migrationProtocols)),
          poolMigrationAddresses(std::move(poolMigrationAddresses)),
          clientStateCallback(std::move(clientStateCallback)),
          serverMigrationEventCallback(
              std::move(serverMigrationEventCallback)){};

    ~ServerTransportFactory() override {
      while (!handlers.empty()) {
        auto& handler = handlers.back();
        handler->evb->runImmediatelyOrRunInEventBaseThreadAndWait(
            [this] { handlers.pop_back(); });
      }
    }

    quic::QuicServerTransport::Ptr make(
        folly::EventBase* eventBase,
        std::unique_ptr<folly::AsyncUDPSocket> sock,
        const folly::SocketAddress&,
        QuicVersion,
        std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept
        override {
      CHECK_EQ(eventBase, sock->getEventBase());
      auto handler = std::make_unique<MessageHandler>(eventBase);
      auto transport = quic::QuicServerTransport::make(
          eventBase, std::move(sock), handler.get(), handler.get(), ctx);

      if (!migrationProtocols.empty()) {
        transport->allowServerMigration(migrationProtocols);
      } else {
        LOG(INFO)
            << "Disabling support for server migration: no protocols available";
      }

      if (!poolMigrationAddresses.empty()) {
        for (auto& address : poolMigrationAddresses) {
          transport->addPoolMigrationAddress(address);
        }
      } else {
        LOG(INFO) << "No pool migration addresses found";
      }

      if (clientStateCallback) {
        transport->setClientStateUpdateCallback(clientStateCallback);
      } else {
        LOG(INFO)
            << "Disabling support for client state updates: no callback available";
      }

      if (serverMigrationEventCallback) {
        transport->setServerMigrationEventCallback(
            serverMigrationEventCallback);
      } else {
        LOG(INFO)
            << "Disabling support for server migration event updates: no callback available";
      }

      handler->setQuicSocket(transport);
      std::lock_guard<std::mutex> guard(handlers_mutex);
      handlers.push_back(std::move(handler));
      return transport;
    }

    std::vector<std::unique_ptr<MessageHandler>> handlers;
    std::mutex handlers_mutex;
    std::unordered_set<ServerMigrationProtocol> migrationProtocols;
    std::unordered_set<QuicIPAddress, QuicIPAddressHash> poolMigrationAddresses;
    std::shared_ptr<ClientStateUpdateCallback> clientStateCallback;
    std::shared_ptr<ServerMigrationEventCallback> serverMigrationEventCallback;
  };

  QuicServerMigrationIntegrationTestServer(
      std::string host,
      uint16_t port,
      std::unordered_set<ServerMigrationProtocol> migrationProtocols,
      std::shared_ptr<ClientStateUpdateCallback> clientStateCallback = nullptr,
      std::shared_ptr<ServerMigrationEventCallback>
          serverMigrationEventCallback = nullptr,
      std::unordered_set<QuicIPAddress, QuicIPAddressHash>
          poolMigrationAddresses =
              std::unordered_set<QuicIPAddress, QuicIPAddressHash>())
      : host(std::move(host)),
        port(port),
        server(QuicServer::createQuicServer()) {
    server->setQuicServerTransportFactory(
        std::make_unique<ServerTransportFactory>(
            std::move(migrationProtocols),
            std::move(poolMigrationAddresses),
            std::move(clientStateCallback),
            std::move(serverMigrationEventCallback)));

    auto serverCtx = quic::test::createServerCtx();
    serverCtx->setClock(std::make_shared<fizz::SystemClock>());
    server->setFizzContext(serverCtx);

    TransportSettings settings;
    settings.disableMigration = false;
    settings.maxNumPTOs = 50;
    settings.selfActiveConnectionIdLimit = 10;
    server->setTransportSettings(settings);
  }

  ~QuicServerMigrationIntegrationTestServer() = default;

  void start() {
    folly::SocketAddress addr(host.c_str(), port);
    server->start(addr, 0);
  }

  std::string host;
  uint16_t port;
  std::shared_ptr<quic::QuicServer> server;
  folly::EventBase* evb;
};

class QuicServerMigrationIntegrationTest : public Test {
  void SetUp() override {
    defaultTestPredicate = [=](QuicError error) {
      EXPECT_NE(error.code.type(), QuicErrorCode::Type::TransportErrorCode);
      if (error.code.type() == QuicErrorCode::Type::LocalErrorCode) {
        auto errorCode = *error.code.asLocalErrorCode();
        EXPECT_EQ(errorCode, LocalErrorCode::SHUTTING_DOWN);
      }
    };
    handshakeRejectedTestPredicate = [=](QuicError error) {
      ASSERT_EQ(error.code.type(), QuicErrorCode::Type::LocalErrorCode);
      EXPECT_EQ(
          *error.code.asLocalErrorCode(), LocalErrorCode::CONNECTION_ABANDONED);
    };
    serverMigratedAbruptlyTestPredicate = [=](QuicError error) {
      ASSERT_EQ(error.code.type(), QuicErrorCode::Type::TransportErrorCode);
      EXPECT_EQ(
          *error.code.asTransportErrorCode(),
          TransportErrorCode::INTERNAL_ERROR);
    };
  }

 public:
  void startServerAndWaitUntilInitialized(
      QuicServerMigrationIntegrationTestServer& server) {
    server.start();
    server.server->waitUntilInitialized();
  }

  void startClientAndWaitUntilHandshakeFinished(
      QuicServerMigrationIntegrationTestClient& client,
      std::function<void(quic::QuicError)>& testPredicate) {
    client.setConnectionErrorTestPredicate(testPredicate);
    client.start();
    client.startDone_.wait();

    // Send a message and wait for the response to be sure
    // that the server has finished the handshake.
    client.send("ping");
    EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
    client.messageReceived.reset();
  }

  template <class Server, class... Clients>
  void shutdownServerAndClients(Server& server, Clients&... clients) {
    (..., clients.close());
    server.server->shutdown();
  }

  std::string serverIP{"127.0.0.1"};
  uint16_t serverPort{50000};
  std::string clientIP{"127.0.0.55"};
  uint16_t clientPort{50001};
  std::unordered_set<ServerMigrationProtocol> serverSupportedProtocols;
  std::unordered_set<ServerMigrationProtocol> clientSupportedProtocols;
  std::unordered_set<QuicIPAddress, QuicIPAddressHash> poolMigrationAddresses;
  std::chrono::seconds batonTimeout{5};

  // Test predicates.
  std::function<void(QuicError)> defaultTestPredicate;
  std::function<void(QuicError)> handshakeRejectedTestPredicate;
  std::function<void(QuicError)> serverMigratedAbruptlyTestPredicate;
};

TEST_F(QuicServerMigrationIntegrationTest, TestNewClientNotified) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);

  auto clientStateUpdateCallback =
      std::make_shared<MockClientStateUpdateCallback>();
  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](folly::SocketAddress clientAddress,
                    Unused,
                    folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                        negotiatedProtocols) {
        EXPECT_EQ(clientAddress.getIPAddress().str(), clientIP);
        EXPECT_EQ(clientAddress.getPort(), clientPort);

        EXPECT_TRUE(negotiatedProtocols.has_value());
        EXPECT_EQ(negotiatedProtocols.value().size(), 1);
        EXPECT_TRUE(negotiatedProtocols.value().count(
            ServerMigrationProtocol::EXPLICIT));
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP, clientPort, serverIP, serverPort, clientSupportedProtocols);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);

  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestConnectionCloseNotified) {
  std::string serverCidHex;
  auto clientStateUpdateCallback =
      std::make_shared<MockClientStateUpdateCallback>();

  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](Unused, ConnectionId serverConnectionId, Unused) {
        serverCidHex = serverConnectionId.hex();
      });
  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverCidHex, serverConnectionId.hex());
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP, clientPort, serverIP, serverPort, clientSupportedProtocols);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);

  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestClientMigrationNotified) {
  folly::SocketAddress clientMigrationAddress("127.0.1.1", 50000);
  ASSERT_NE(clientMigrationAddress.getIPAddress().str(), clientIP);

  std::string serverCidHex;
  auto clientStateUpdateCallback =
      std::make_shared<MockClientStateUpdateCallback>();

  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](Unused, ConnectionId serverConnectionId, Unused) {
        serverCidHex = serverConnectionId.hex();
      });
  EXPECT_CALL(*clientStateUpdateCallback, onClientMigrationDetected)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId,
                    folly::SocketAddress newClientAddress) {
        EXPECT_EQ(serverCidHex, serverConnectionId.hex());
        EXPECT_EQ(clientMigrationAddress, newClientAddress);
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP, clientPort, serverIP, serverPort, clientSupportedProtocols);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);

  // Migrate client.
  auto newClientSocket =
      std::make_unique<folly::AsyncUDPSocket>(client.transport->getEventBase());
  newClientSocket->bind(clientMigrationAddress);
  client.transport->onNetworkSwitch(std::move(newClientSocket));

  // Send a message from the new address to test reachability.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestSuccessfulNegotiation) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);

  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);

  auto clientStateUpdateCallback =
      std::make_shared<MockClientStateUpdateCallback>();
  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](Unused,
                    Unused,
                    folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                        negotiatedProtocols) {
        EXPECT_TRUE(negotiatedProtocols.has_value());
        EXPECT_EQ(negotiatedProtocols.value().size(), 2);
        EXPECT_TRUE(negotiatedProtocols.value().count(
            ServerMigrationProtocol::SYMMETRIC));
        EXPECT_TRUE(negotiatedProtocols.value().count(
            ServerMigrationProtocol::POOL_OF_ADDRESSES));
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP, clientPort, serverIP, serverPort, clientSupportedProtocols);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);

  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestUnsuccessfulNegotiation) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);

  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);

  auto clientStateUpdateCallback =
      std::make_shared<MockClientStateUpdateCallback>();
  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](Unused,
                    Unused,
                    folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                        negotiatedProtocols) {
        EXPECT_TRUE(negotiatedProtocols.has_value());
        EXPECT_TRUE(negotiatedProtocols.value().empty());
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP, clientPort, serverIP, serverPort, clientSupportedProtocols);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);

  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestNoNegotiation) {
  // serverSupportedProtocols and clientSupportedProtocols are
  // left empty, so that the server migration support is automatically
  // disabled by the test classes.

  auto clientStateUpdateCallback =
      std::make_shared<MockClientStateUpdateCallback>();
  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](Unused,
                    Unused,
                    folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                        negotiatedProtocols) {
        EXPECT_FALSE(negotiatedProtocols.has_value());
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP, clientPort, serverIP, serverPort, clientSupportedProtocols);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);

  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestSendPoolMigrationAddresses) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.1"), 1234));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.2"), 4567));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.3"), 8910));

  std::string serverCidHex;
  auto clientStateUpdateCallback =
      std::make_shared<MockClientStateUpdateCallback>();
  auto serverMigrationEventCallbackServerSide =
      std::make_shared<MockServerMigrationEventCallback>();
  auto serverMigrationEventCallbackClientSide =
      std::make_shared<MockServerMigrationEventCallback>();

  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](Unused,
                    ConnectionId serverConnectionId,
                    folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                        negotiatedProtocols) {
        ASSERT_TRUE(negotiatedProtocols.has_value());
        EXPECT_EQ(negotiatedProtocols->size(), 1);
        EXPECT_TRUE(negotiatedProtocols->count(
            ServerMigrationProtocol::POOL_OF_ADDRESSES));
        serverCidHex = serverConnectionId.hex();
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onPoolMigrationAddressReceived)
      .Times(Exactly(poolMigrationAddresses.size()))
      .WillRepeatedly([&](PoolMigrationAddressFrame frame) {
        auto it = poolMigrationAddresses.find(frame.address);
        EXPECT_NE(it, poolMigrationAddresses.end());
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide,
      onPoolMigrationAddressAckReceived)
      .Times(Exactly(poolMigrationAddresses.size()))
      .WillRepeatedly([&](ConnectionId serverConnectionId,
                          PoolMigrationAddressFrame frame) {
        EXPECT_EQ(serverCidHex, serverConnectionId.hex());
        auto it = poolMigrationAddresses.find(frame.address);
        EXPECT_NE(it, poolMigrationAddresses.end());
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback,
      serverMigrationEventCallbackServerSide,
      poolMigrationAddresses);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackClientSide);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);

  // Send a message after the handshake is finished, to be sure that the
  // acknowledgements for the POOL_MIGRATION_ADDRESS frames are received
  // by the server.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestPoolMigrationAddressesWithUnsuccessfulNegotiation) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.1"), 1234));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.2"), 4567));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.3"), 8910));

  auto serverMigrationEventCallbackServerSide =
      std::make_shared<MockServerMigrationEventCallback>();
  auto serverMigrationEventCallbackClientSide =
      std::make_shared<MockServerMigrationEventCallback>();

  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onPoolMigrationAddressReceived)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide,
      onPoolMigrationAddressAckReceived)
      .Times(0);

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      nullptr,
      serverMigrationEventCallbackServerSide,
      poolMigrationAddresses);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackClientSide);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);

  // Send a message after the handshake is finished, to be sure that the
  // acknowledgements for the POOL_MIGRATION_ADDRESS frames are received
  // by the server.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestPoolMigrationAddressesWithNoNegotiation) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.1"), 1234));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.2"), 4567));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.3"), 8910));

  auto serverMigrationEventCallbackServerSide =
      std::make_shared<MockServerMigrationEventCallback>();
  auto serverMigrationEventCallbackClientSide =
      std::make_shared<MockServerMigrationEventCallback>();

  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onPoolMigrationAddressReceived)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide,
      onPoolMigrationAddressAckReceived)
      .Times(0);

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      nullptr,
      serverMigrationEventCallbackServerSide,
      poolMigrationAddresses);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackClientSide);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);

  // Send a message after the handshake is finished, to be sure that the
  // acknowledgements for the POOL_MIGRATION_ADDRESS frames are received
  // by the server.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestPoolMigrationAddressesWithDifferentProtocolNegotiated) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.1"), 1234));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.2"), 4567));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.3"), 8910));

  auto serverMigrationEventCallbackServerSide =
      std::make_shared<MockServerMigrationEventCallback>();
  auto serverMigrationEventCallbackClientSide =
      std::make_shared<MockServerMigrationEventCallback>();

  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onPoolMigrationAddressReceived)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide,
      onPoolMigrationAddressAckReceived)
      .Times(0);

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      nullptr,
      serverMigrationEventCallbackServerSide,
      poolMigrationAddresses);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackClientSide);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);

  // Send a message after the handshake is finished, to be sure that the
  // acknowledgements for the POOL_MIGRATION_ADDRESS frames are received
  // by the server.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestExplicitProtocolMigration) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  std::string serverCidHex;

  auto clientStateUpdateCallback =
      std::make_shared<StrictMock<MockClientStateUpdateCallback>>();
  auto serverMigrationEventCallbackServerSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackClientSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();

  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](folly::SocketAddress clientAddress,
                    ConnectionId serverConnectionId,
                    folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                        negotiatedProtocols) {
        EXPECT_EQ(clientAddress, folly::SocketAddress(clientIP, clientPort));
        ASSERT_TRUE(negotiatedProtocols.has_value());
        EXPECT_EQ(negotiatedProtocols->size(), 1);
        EXPECT_TRUE(
            negotiatedProtocols->count(ServerMigrationProtocol::EXPLICIT));
        serverCidHex = serverConnectionId.hex();
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback,
      serverMigrationEventCallbackServerSide);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackClientSide);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);
  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());

  // Notify imminent server migration.
  folly::fibers::Baton serverMigrationReadyBaton;
  folly::SocketAddress serverMigrationAddress("127.0.1.1", 6000);
  QuicIPAddress quicIpServerMigrationAddress(serverMigrationAddress);
  ASSERT_NE(serverMigrationAddress, folly::SocketAddress(serverIP, serverPort));

  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        EXPECT_EQ(frame, ServerMigrationFrame(quicIpServerMigrationAddress));
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationAckReceived)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId,
                    ServerMigrationFrame frame) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        EXPECT_EQ(frame, ServerMigrationFrame(quicIpServerMigrationAddress));
      });
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationReady)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationReadyBaton.post();
      });

  server.server->onImminentServerMigration(
      ServerMigrationProtocol::EXPLICIT, quicIpServerMigrationAddress);
  EXPECT_TRUE(serverMigrationReadyBaton.try_wait_for(batonTimeout));
  serverMigrationReadyBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Start the migration.
  folly::fibers::Baton serverMigrationCompletedBaton;
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationProbingStarted)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationProtocol protocol,
                    folly::SocketAddress probingAddress) {
        EXPECT_EQ(protocol, ServerMigrationProtocol::EXPLICIT);
        EXPECT_EQ(probingAddress, serverMigrationAddress);
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationCompleted())
      .Times(Exactly(1));
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationCompleted(_))
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationCompletedBaton.post();
      });

  server.server->onNetworkSwitch(serverMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), serverMigrationAddress);
  client.send("probing");
  EXPECT_TRUE(serverMigrationCompletedBaton.try_wait_for(batonTimeout));
  serverMigrationCompletedBaton.reset();
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
      });
  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestPoolOfAddressesProtocolMigration) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.1"), 1234));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.2"), 4567));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.3"), 8910));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.4"), 1112));
  std::string serverCidHex;

  auto clientStateUpdateCallback =
      std::make_shared<StrictMock<MockClientStateUpdateCallback>>();
  auto serverMigrationEventCallbackServerSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackClientSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();

  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](folly::SocketAddress clientAddress,
                    ConnectionId serverConnectionId,
                    folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                        negotiatedProtocols) {
        EXPECT_EQ(clientAddress, folly::SocketAddress(clientIP, clientPort));
        ASSERT_TRUE(negotiatedProtocols.has_value());
        EXPECT_EQ(negotiatedProtocols->size(), 1);
        EXPECT_TRUE(negotiatedProtocols->count(
            ServerMigrationProtocol::POOL_OF_ADDRESSES));
        serverCidHex = serverConnectionId.hex();
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onPoolMigrationAddressReceived)
      .Times(Exactly(poolMigrationAddresses.size()))
      .WillRepeatedly([&](PoolMigrationAddressFrame frame) {
        auto it = poolMigrationAddresses.find(frame.address);
        EXPECT_NE(it, poolMigrationAddresses.end());
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide,
      onPoolMigrationAddressAckReceived)
      .Times(Exactly(poolMigrationAddresses.size()))
      .WillRepeatedly([&](ConnectionId serverConnectionId,
                          PoolMigrationAddressFrame frame) {
        EXPECT_EQ(serverCidHex, serverConnectionId.hex());
        auto it = poolMigrationAddresses.find(frame.address);
        EXPECT_NE(it, poolMigrationAddresses.end());
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback,
      serverMigrationEventCallbackServerSide,
      poolMigrationAddresses);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackClientSide);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);

  // Send a message after the handshake is finished, to be sure that the
  // acknowledgements for the POOL_MIGRATION_ADDRESS frames are received
  // by the server.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Before starting the migration, wait a bit to be sure that the ACK for the
  // echo message is received by the server. This avoids a particular case where
  // the call to onNetworkSwitch() happens before the server receives this ACK,
  // causing a PTO in the server just after the migration. Due to the PTO, the
  // server sends a PING message from the new address, right in the middle of
  // the migration probing done by the client, concluding it and forcing the
  // client to send a PATH_CHALLENGE. This behaviour is correct and satisfies
  // the requirements of the Pool of Addresses protocol, but "hides" the
  // migration probing in the network traces, so it is better to avoid it in
  // this context. Note that the test still succeeds if the wait is removed.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // Notify imminent server migration.
  folly::fibers::Baton serverMigrationReadyBaton;
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationReady)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationReadyBaton.post();
      });

  server.server->onImminentServerMigration(
      ServerMigrationProtocol::POOL_OF_ADDRESSES, folly::none);
  EXPECT_TRUE(serverMigrationReadyBaton.try_wait_for(batonTimeout));
  serverMigrationReadyBaton.reset();
  Mock::VerifyAndClearExpectations(&serverMigrationEventCallbackServerSide);

  // Start the migration.
  folly::fibers::Baton serverMigrationCompletedBaton;
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationProbingStarted)
      .Times(AtLeast(1))
      .WillRepeatedly([&](ServerMigrationProtocol protocol,
                          folly::SocketAddress probingAddress) {
        EXPECT_EQ(protocol, ServerMigrationProtocol::POOL_OF_ADDRESSES);
        auto it = poolMigrationAddresses.find(QuicIPAddress(probingAddress));
        EXPECT_TRUE(
            it != poolMigrationAddresses.end() ||
            probingAddress == folly::SocketAddress(serverIP, serverPort));
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationCompleted())
      .Times(Exactly(1));
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationCompleted(_))
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationCompletedBaton.post();
      });

  folly::SocketAddress serverMigrationAddress("127.1.1.4", 1112);
  ASSERT_TRUE(
      poolMigrationAddresses.count(QuicIPAddress(serverMigrationAddress)));
  ASSERT_NE(serverMigrationAddress, folly::SocketAddress(serverIP, serverPort));

  server.server->onNetworkSwitch(serverMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), serverMigrationAddress);
  client.send("probing");
  EXPECT_TRUE(serverMigrationCompletedBaton.try_wait_for(batonTimeout));
  serverMigrationCompletedBaton.reset();
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();
  Mock::VerifyAndClearExpectations(&serverMigrationEventCallbackClientSide);
  Mock::VerifyAndClearExpectations(&serverMigrationEventCallbackServerSide);

  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
      });
  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestSymmetricProtocolMigration) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  std::string serverCidHex;

  auto clientStateUpdateCallback =
      std::make_shared<StrictMock<MockClientStateUpdateCallback>>();
  auto serverMigrationEventCallbackServerSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackClientSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();

  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](folly::SocketAddress clientAddress,
                    ConnectionId serverConnectionId,
                    folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                        negotiatedProtocols) {
        EXPECT_EQ(clientAddress, folly::SocketAddress(clientIP, clientPort));
        ASSERT_TRUE(negotiatedProtocols.has_value());
        EXPECT_EQ(negotiatedProtocols->size(), 1);
        EXPECT_TRUE(
            negotiatedProtocols->count(ServerMigrationProtocol::SYMMETRIC));
        serverCidHex = serverConnectionId.hex();
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback,
      serverMigrationEventCallbackServerSide);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackClientSide);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);
  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());

  // Notify imminent server migration.
  folly::fibers::Baton serverMigrationReadyBaton;
  folly::SocketAddress serverMigrationAddress("127.0.1.1", 6000);
  ASSERT_NE(serverMigrationAddress, folly::SocketAddress(serverIP, serverPort));

  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationReady)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationReadyBaton.post();
      });

  server.server->onImminentServerMigration(
      ServerMigrationProtocol::SYMMETRIC, folly::none);
  EXPECT_TRUE(serverMigrationReadyBaton.try_wait_for(batonTimeout));
  serverMigrationReadyBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Start the migration.
  folly::fibers::Baton serverMigrationCompletedBaton;
  EXPECT_CALL(*serverMigrationEventCallbackClientSide, onServerMigratedReceived)
      .Times(AtMost(1));
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationCompleted())
      .Times(Exactly(1));
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigratedAckReceived)
      .Times(AtMost(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationCompleted(_))
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationCompletedBaton.post();
      });

  server.server->onNetworkSwitch(serverMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), serverMigrationAddress);
  EXPECT_TRUE(serverMigrationCompletedBaton.try_wait_for(batonTimeout));
  serverMigrationCompletedBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Test reachability.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
      });
  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestSynchronizedSymmetricProtocolMigration) {
  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  std::string serverCidHex;

  auto clientStateUpdateCallback =
      std::make_shared<StrictMock<MockClientStateUpdateCallback>>();
  auto serverMigrationEventCallbackServerSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackClientSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();

  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](folly::SocketAddress clientAddress,
                    ConnectionId serverConnectionId,
                    folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                        negotiatedProtocols) {
        EXPECT_EQ(clientAddress, folly::SocketAddress(clientIP, clientPort));
        ASSERT_TRUE(negotiatedProtocols.has_value());
        EXPECT_EQ(negotiatedProtocols->size(), 1);
        EXPECT_TRUE(negotiatedProtocols->count(
            ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC));
        serverCidHex = serverConnectionId.hex();
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback,
      serverMigrationEventCallbackServerSide);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackClientSide);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);
  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());

  // Notify imminent server migration.
  folly::fibers::Baton serverMigrationReadyBaton;
  folly::SocketAddress serverMigrationAddress("127.0.1.1", 6000);
  ASSERT_NE(serverMigrationAddress, folly::SocketAddress(serverIP, serverPort));

  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        QuicIPAddress emptyAddress;
        EXPECT_EQ(frame, ServerMigrationFrame(emptyAddress));
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationAckReceived)
      .Times(Exactly(1))
      .WillOnce(
          [&](ConnectionId serverConnectionId, ServerMigrationFrame frame) {
            QuicIPAddress emptyAddress;
            EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
            EXPECT_EQ(frame, ServerMigrationFrame(emptyAddress));
          });
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationReady)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationReadyBaton.post();
      });

  server.server->onImminentServerMigration(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC, folly::none);
  EXPECT_TRUE(serverMigrationReadyBaton.try_wait_for(batonTimeout));
  serverMigrationReadyBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Start the migration.
  folly::fibers::Baton serverMigrationCompletedBaton;
  EXPECT_CALL(*serverMigrationEventCallbackClientSide, onServerMigratedReceived)
      .Times(AtMost(1));
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationCompleted())
      .Times(Exactly(1));
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigratedAckReceived)
      .Times(AtMost(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationCompleted(_))
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationCompletedBaton.post();
      });

  server.server->onNetworkSwitch(serverMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), serverMigrationAddress);
  EXPECT_TRUE(serverMigrationCompletedBaton.try_wait_for(batonTimeout));
  serverMigrationCompletedBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Test reachability.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
      });
  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestRejectNewConnectionsDuringMigration) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  std::string serverCidHex;

  auto clientStateUpdateCallback =
      std::make_shared<StrictMock<MockClientStateUpdateCallback>>();
  auto serverMigrationEventCallbackServerSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackClientSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback,
      serverMigrationEventCallbackServerSide);
  startServerAndWaitUntilInitialized(server);

  // Notify imminent server migration. Since no clients are connected to the
  // server, this operation will only block handshakes from new clients until
  // onNetworkSwitch() is called. No calls to onServerMigrationFailed() or
  // onServerMigrationReady() are expected.
  folly::SocketAddress serverMigrationAddress("127.0.1.1", 6000);
  ASSERT_NE(serverMigrationAddress, folly::SocketAddress(serverIP, serverPort));
  server.server->onImminentServerMigration(
      ServerMigrationProtocol::SYMMETRIC, folly::none);

  // Try to connect a client. This attempt should be rejected.
  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished).Times(0);
  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose).Times(0);
  QuicServerMigrationIntegrationTestClient rejectedClient(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackClientSide);
  rejectedClient.setConnectionErrorTestPredicate(
      handshakeRejectedTestPredicate);
  rejectedClient.start();
  rejectedClient.startDone_.wait();
  rejectedClient.close();
  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());

  // Complete the server migration and unblock the new handshakes.
  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](folly::SocketAddress clientAddress,
                    ConnectionId serverConnectionId,
                    folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                        negotiatedProtocols) {
        EXPECT_EQ(clientAddress, folly::SocketAddress(clientIP, clientPort));
        ASSERT_TRUE(negotiatedProtocols.has_value());
        EXPECT_EQ(negotiatedProtocols->size(), 1);
        EXPECT_TRUE(
            negotiatedProtocols->count(ServerMigrationProtocol::SYMMETRIC));
        serverCidHex = serverConnectionId.hex();
      });

  server.server->onNetworkSwitch(serverMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), serverMigrationAddress);

  QuicServerMigrationIntegrationTestClient acceptedClient(
      clientIP,
      clientPort,
      serverMigrationAddress.getAddressStr(),
      serverMigrationAddress.getPort(),
      clientSupportedProtocols,
      serverMigrationEventCallbackClientSide);
  startClientAndWaitUntilHandshakeFinished(
      acceptedClient, defaultTestPredicate);
  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());

  // Close the connection.
  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
      });
  shutdownServerAndClients(server, acceptedClient);
}

TEST_F(QuicServerMigrationIntegrationTest, TestMigrateChangingOnlyThePort) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  std::string serverCidHex;

  auto clientStateUpdateCallback =
      std::make_shared<StrictMock<MockClientStateUpdateCallback>>();
  auto serverMigrationEventCallbackServerSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackClientSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();

  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](folly::SocketAddress clientAddress,
                    ConnectionId serverConnectionId,
                    folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                        negotiatedProtocols) {
        EXPECT_EQ(clientAddress, folly::SocketAddress(clientIP, clientPort));
        ASSERT_TRUE(negotiatedProtocols.has_value());
        EXPECT_EQ(negotiatedProtocols->size(), 1);
        EXPECT_TRUE(
            negotiatedProtocols->count(ServerMigrationProtocol::SYMMETRIC));
        serverCidHex = serverConnectionId.hex();
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback,
      serverMigrationEventCallbackServerSide);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackClientSide);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);
  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());

  // Notify imminent server migration.
  folly::fibers::Baton serverMigrationReadyBaton;
  folly::SocketAddress serverMigrationAddress(serverIP, serverPort + 1);
  ASSERT_EQ(serverMigrationAddress.getAddressStr(), serverIP);
  ASSERT_NE(serverMigrationAddress.getPort(), 0);
  ASSERT_NE(serverMigrationAddress.getPort(), serverPort);

  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationReady)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationReadyBaton.post();
      });

  server.server->onImminentServerMigration(
      ServerMigrationProtocol::SYMMETRIC, folly::none);
  EXPECT_TRUE(serverMigrationReadyBaton.try_wait_for(batonTimeout));
  serverMigrationReadyBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Start the migration.
  folly::fibers::Baton serverMigrationCompletedBaton;
  EXPECT_CALL(*serverMigrationEventCallbackClientSide, onServerMigratedReceived)
      .Times(AtMost(1));
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationCompleted())
      .Times(Exactly(1));
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigratedAckReceived)
      .Times(AtMost(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationCompleted(_))
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationCompletedBaton.post();
      });

  server.server->onNetworkSwitch(serverMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), serverMigrationAddress);
  EXPECT_TRUE(serverMigrationCompletedBaton.try_wait_for(batonTimeout));
  serverMigrationCompletedBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Test reachability.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
      });
  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestMigrateMultipleTransportsWithDifferentProtocolsAtTheSameTime) {
  // Server variables.
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);

  folly::SocketAddress serverMigrationAddress("127.0.1.1", 6000);
  QuicIPAddress quicIpServerMigrationAddress(serverMigrationAddress);
  ASSERT_NE(serverMigrationAddress, folly::SocketAddress(serverIP, serverPort));

  auto clientStateUpdateCallback =
      std::make_shared<StrictMock<MockClientStateUpdateCallback>>();
  auto serverMigrationEventCallbackServerSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  std::unordered_map<folly::SocketAddress, ConnectionId> serverCids;

  // Client variables.
  // All clients support the same protocols, but each one will
  // use a different one during the server migration.
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);

  folly::SocketAddress firstClientAddress =
      folly::SocketAddress("127.1.1.1", 50001);
  folly::SocketAddress secondClientAddress =
      folly::SocketAddress("127.2.2.2", 50002);
  folly::SocketAddress thirdClientAddress =
      folly::SocketAddress("127.3.3.3", 50003);

  auto serverMigrationEventCallbackFirstClient =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackSecondClient =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackThirdClient =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();

  // First step: connect all the clients (sequentially for simplicity).
  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(3))
      .WillRepeatedly(
          [&](folly::SocketAddress clientAddress,
              ConnectionId serverConnectionId,
              folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                  negotiatedProtocols) {
            EXPECT_TRUE(
                clientAddress == firstClientAddress ||
                clientAddress == secondClientAddress ||
                clientAddress == thirdClientAddress);
            ASSERT_TRUE(negotiatedProtocols.has_value());
            EXPECT_EQ(negotiatedProtocols->size(), 3);
            EXPECT_TRUE(
                negotiatedProtocols->count(ServerMigrationProtocol::EXPLICIT));
            EXPECT_TRUE(
                negotiatedProtocols->count(ServerMigrationProtocol::SYMMETRIC));
            EXPECT_TRUE(negotiatedProtocols->count(
                ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC));
            std::vector<uint8_t> connId(
                serverConnectionId.data(),
                serverConnectionId.data() + serverConnectionId.size());
            serverCids.emplace(clientAddress, ConnectionId{connId});
          });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback,
      serverMigrationEventCallbackServerSide);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient firstClient(
      firstClientAddress.getAddressStr(),
      firstClientAddress.getPort(),
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackFirstClient);
  startClientAndWaitUntilHandshakeFinished(firstClient, defaultTestPredicate);

  QuicServerMigrationIntegrationTestClient secondClient(
      secondClientAddress.getAddressStr(),
      secondClientAddress.getPort(),
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackSecondClient);
  startClientAndWaitUntilHandshakeFinished(secondClient, defaultTestPredicate);

  QuicServerMigrationIntegrationTestClient thirdClient(
      thirdClientAddress.getAddressStr(),
      thirdClientAddress.getPort(),
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackThirdClient);
  startClientAndWaitUntilHandshakeFinished(thirdClient, defaultTestPredicate);
  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());

  // Second step: notify imminent server migration using:
  // 1) the Explicit protocol for the first client;
  // 2) the Symmetric protocol for the second client;
  // 3) the Synchronized Symmetric protocol for the third client.
  folly::fibers::Baton serverMigrationReadyBaton;
  std::atomic<int> nServerTransportsReady = 0;

  QuicServer::ServerMigrationSettings migrationSettings;
  migrationSettings[serverCids.at(firstClientAddress)] = std::make_pair(
      ServerMigrationProtocol::EXPLICIT, quicIpServerMigrationAddress);
  migrationSettings[serverCids.at(secondClientAddress)] =
      std::make_pair(ServerMigrationProtocol::SYMMETRIC, folly::none);
  migrationSettings[serverCids.at(thirdClientAddress)] = std::make_pair(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC, folly::none);

  EXPECT_CALL(
      *serverMigrationEventCallbackFirstClient, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        EXPECT_EQ(frame, ServerMigrationFrame(quicIpServerMigrationAddress));
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackThirdClient, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        QuicIPAddress emptyAddress;
        EXPECT_EQ(frame, ServerMigrationFrame(emptyAddress));
      });

  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationAckReceived)
      .Times(Exactly(2))
      .WillRepeatedly(
          [&](ConnectionId serverConnectionId, ServerMigrationFrame frame) {
            if (frame.address.isAllZero()) {
              EXPECT_EQ(serverConnectionId, serverCids.at(thirdClientAddress));
            } else {
              EXPECT_EQ(serverConnectionId, serverCids.at(firstClientAddress));
            }
          });
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationReady)
      .Times(Exactly(3))
      .WillRepeatedly([&](ConnectionId serverConnectionId) {
        EXPECT_TRUE(
            serverConnectionId == serverCids.at(firstClientAddress) ||
            serverConnectionId == serverCids.at(secondClientAddress) ||
            serverConnectionId == serverCids.at(thirdClientAddress));
        ++nServerTransportsReady;
        if (nServerTransportsReady == 3) {
          serverMigrationReadyBaton.post();
        }
      });

  server.server->onImminentServerMigration(migrationSettings);
  EXPECT_TRUE(serverMigrationReadyBaton.try_wait_for(batonTimeout));
  serverMigrationReadyBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackFirstClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackSecondClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackThirdClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Third step: start the server migration.
  folly::fibers::Baton serverMigrationCompletedBaton;
  std::atomic<int> nServerTransportsMigrated = 0;

  EXPECT_CALL(
      *serverMigrationEventCallbackFirstClient, onServerMigrationProbingStarted)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationProtocol protocol,
                    folly::SocketAddress probingAddress) {
        EXPECT_EQ(protocol, ServerMigrationProtocol::EXPLICIT);
        EXPECT_EQ(probingAddress, serverMigrationAddress);
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackFirstClient, onServerMigrationCompleted())
      .Times(Exactly(1));

  EXPECT_CALL(
      *serverMigrationEventCallbackSecondClient, onServerMigratedReceived)
      .Times(AtMost(1));
  EXPECT_CALL(
      *serverMigrationEventCallbackSecondClient, onServerMigrationCompleted())
      .Times(Exactly(1));

  EXPECT_CALL(
      *serverMigrationEventCallbackThirdClient, onServerMigratedReceived)
      .Times(AtMost(1));
  EXPECT_CALL(
      *serverMigrationEventCallbackThirdClient, onServerMigrationCompleted())
      .Times(Exactly(1));

  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigratedAckReceived)
      .Times(AtMost(2))
      .WillRepeatedly([&](ConnectionId serverConnectionId) {
        EXPECT_TRUE(
            serverConnectionId == serverCids.at(secondClientAddress) ||
            serverConnectionId == serverCids.at(thirdClientAddress));
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationCompleted(_))
      .Times(Exactly(3))
      .WillRepeatedly([&](ConnectionId serverConnectionId) {
        EXPECT_TRUE(
            serverConnectionId == serverCids.at(firstClientAddress) ||
            serverConnectionId == serverCids.at(secondClientAddress) ||
            serverConnectionId == serverCids.at(thirdClientAddress));
        ++nServerTransportsMigrated;
        if (nServerTransportsMigrated == 3) {
          serverMigrationCompletedBaton.post();
        }
      });

  server.server->onNetworkSwitch(serverMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), serverMigrationAddress);

  // Send a message from the first client (the one using the
  // Explicit protocol), so that it detects the loss and starts probing.
  firstClient.send("probing");

  EXPECT_TRUE(serverMigrationCompletedBaton.try_wait_for(batonTimeout));
  serverMigrationCompletedBaton.reset();
  EXPECT_TRUE(firstClient.messageReceived.try_wait_for(batonTimeout));
  firstClient.messageReceived.reset();

  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackFirstClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackSecondClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackThirdClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Fourth step: try to send a message from each client
  // to the server to test reachability.
  firstClient.send("ping");
  secondClient.send("ping");
  thirdClient.send("ping");

  EXPECT_TRUE(firstClient.messageReceived.try_wait_for(batonTimeout));
  firstClient.messageReceived.reset();
  EXPECT_TRUE(secondClient.messageReceived.try_wait_for(batonTimeout));
  secondClient.messageReceived.reset();
  EXPECT_TRUE(thirdClient.messageReceived.try_wait_for(batonTimeout));
  thirdClient.messageReceived.reset();

  // Last step: close the connections.
  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose)
      .Times(Exactly(3))
      .WillRepeatedly([&](ConnectionId serverConnectionId) {
        EXPECT_TRUE(
            serverConnectionId == serverCids.at(firstClientAddress) ||
            serverConnectionId == serverCids.at(secondClientAddress) ||
            serverConnectionId == serverCids.at(thirdClientAddress));
      });
  shutdownServerAndClients(server, firstClient, secondClient, thirdClient);
}

TEST_F(QuicServerMigrationIntegrationTest, TestMigrateMultipleTransportsWithTheSameProtocolAtTheSameTime) {
  // Server variables.
  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  folly::SocketAddress serverMigrationAddress("127.0.1.1", 6000);
  ASSERT_NE(serverMigrationAddress, folly::SocketAddress(serverIP, serverPort));

  auto clientStateUpdateCallback =
      std::make_shared<StrictMock<MockClientStateUpdateCallback>>();
  auto serverMigrationEventCallbackServerSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  std::unordered_map<folly::SocketAddress, ConnectionId> serverCids;

  // Client variables.
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  folly::SocketAddress firstClientAddress =
      folly::SocketAddress("127.1.1.1", 50001);
  folly::SocketAddress secondClientAddress =
      folly::SocketAddress("127.2.2.2", 50002);
  folly::SocketAddress thirdClientAddress =
      folly::SocketAddress("127.3.3.3", 50003);

  auto serverMigrationEventCallbackFirstClient =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackSecondClient =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackThirdClient =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();

  // First step: connect all the clients (sequentially for simplicity).
  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(3))
      .WillRepeatedly(
          [&](folly::SocketAddress clientAddress,
              ConnectionId serverConnectionId,
              folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                  negotiatedProtocols) {
            EXPECT_TRUE(
                clientAddress == firstClientAddress ||
                clientAddress == secondClientAddress ||
                clientAddress == thirdClientAddress);
            ASSERT_TRUE(negotiatedProtocols.has_value());
            EXPECT_EQ(negotiatedProtocols->size(), 1);
            EXPECT_TRUE(negotiatedProtocols->count(
                ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC));
            std::vector<uint8_t> connId(
                serverConnectionId.data(),
                serverConnectionId.data() + serverConnectionId.size());
            serverCids.emplace(clientAddress, ConnectionId{connId});
          });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback,
      serverMigrationEventCallbackServerSide);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient firstClient(
      firstClientAddress.getAddressStr(),
      firstClientAddress.getPort(),
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackFirstClient);
  startClientAndWaitUntilHandshakeFinished(firstClient, defaultTestPredicate);

  QuicServerMigrationIntegrationTestClient secondClient(
      secondClientAddress.getAddressStr(),
      secondClientAddress.getPort(),
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackSecondClient);
  startClientAndWaitUntilHandshakeFinished(secondClient, defaultTestPredicate);

  QuicServerMigrationIntegrationTestClient thirdClient(
      thirdClientAddress.getAddressStr(),
      thirdClientAddress.getPort(),
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackThirdClient);
  startClientAndWaitUntilHandshakeFinished(thirdClient, defaultTestPredicate);
  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());

  // Second step: notify imminent server migration.
  folly::fibers::Baton serverMigrationReadyBaton;
  std::atomic<int> nServerTransportsReady = 0;

  EXPECT_CALL(
      *serverMigrationEventCallbackFirstClient, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        QuicIPAddress emptyAddress;
        EXPECT_EQ(frame, ServerMigrationFrame(emptyAddress));
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackSecondClient, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        QuicIPAddress emptyAddress;
        EXPECT_EQ(frame, ServerMigrationFrame(emptyAddress));
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackThirdClient, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        QuicIPAddress emptyAddress;
        EXPECT_EQ(frame, ServerMigrationFrame(emptyAddress));
      });

  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationAckReceived)
      .Times(Exactly(3))
      .WillRepeatedly(
          [&](ConnectionId serverConnectionId, ServerMigrationFrame frame) {
            EXPECT_TRUE(frame.address.isAllZero());
            EXPECT_TRUE(
                serverConnectionId == serverCids.at(firstClientAddress) ||
                serverConnectionId == serverCids.at(secondClientAddress) ||
                serverConnectionId == serverCids.at(thirdClientAddress));
          });
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationReady)
      .Times(Exactly(3))
      .WillRepeatedly([&](ConnectionId serverConnectionId) {
        EXPECT_TRUE(
            serverConnectionId == serverCids.at(firstClientAddress) ||
            serverConnectionId == serverCids.at(secondClientAddress) ||
            serverConnectionId == serverCids.at(thirdClientAddress));
        ++nServerTransportsReady;
        if (nServerTransportsReady == 3) {
          serverMigrationReadyBaton.post();
        }
      });

  server.server->onImminentServerMigration(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC, folly::none);
  EXPECT_TRUE(serverMigrationReadyBaton.try_wait_for(batonTimeout));
  serverMigrationReadyBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackFirstClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackSecondClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackThirdClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Third step: start the server migration.
  folly::fibers::Baton serverMigrationCompletedBaton;
  std::atomic<int> nServerTransportsMigrated = 0;

  EXPECT_CALL(
      *serverMigrationEventCallbackFirstClient, onServerMigratedReceived)
      .Times(AtMost(1));
  EXPECT_CALL(
      *serverMigrationEventCallbackFirstClient, onServerMigrationCompleted())
      .Times(Exactly(1));

  EXPECT_CALL(
      *serverMigrationEventCallbackSecondClient, onServerMigratedReceived)
      .Times(AtMost(1));
  EXPECT_CALL(
      *serverMigrationEventCallbackSecondClient, onServerMigrationCompleted())
      .Times(Exactly(1));

  EXPECT_CALL(
      *serverMigrationEventCallbackThirdClient, onServerMigratedReceived)
      .Times(AtMost(1));
  EXPECT_CALL(
      *serverMigrationEventCallbackThirdClient, onServerMigrationCompleted())
      .Times(Exactly(1));

  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigratedAckReceived)
      .Times(AtMost(3))
      .WillRepeatedly([&](ConnectionId serverConnectionId) {
        EXPECT_TRUE(
            serverConnectionId == serverCids.at(firstClientAddress) ||
            serverConnectionId == serverCids.at(secondClientAddress) ||
            serverConnectionId == serverCids.at(thirdClientAddress));
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationCompleted(_))
      .Times(Exactly(3))
      .WillRepeatedly([&](ConnectionId serverConnectionId) {
        EXPECT_TRUE(
            serverConnectionId == serverCids.at(firstClientAddress) ||
            serverConnectionId == serverCids.at(secondClientAddress) ||
            serverConnectionId == serverCids.at(thirdClientAddress));
        ++nServerTransportsMigrated;
        if (nServerTransportsMigrated == 3) {
          serverMigrationCompletedBaton.post();
        }
      });

  server.server->onNetworkSwitch(serverMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), serverMigrationAddress);
  EXPECT_TRUE(serverMigrationCompletedBaton.try_wait_for(batonTimeout));
  serverMigrationCompletedBaton.reset();

  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackFirstClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackSecondClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackThirdClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Fourth step: try to send a message from each client
  // to the server to test reachability.
  firstClient.send("ping");
  secondClient.send("ping");
  thirdClient.send("ping");

  EXPECT_TRUE(firstClient.messageReceived.try_wait_for(batonTimeout));
  firstClient.messageReceived.reset();
  EXPECT_TRUE(secondClient.messageReceived.try_wait_for(batonTimeout));
  secondClient.messageReceived.reset();
  EXPECT_TRUE(thirdClient.messageReceived.try_wait_for(batonTimeout));
  thirdClient.messageReceived.reset();

  // Last step: close the connections.
  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose)
      .Times(Exactly(3))
      .WillRepeatedly([&](ConnectionId serverConnectionId) {
        EXPECT_TRUE(
            serverConnectionId == serverCids.at(firstClientAddress) ||
            serverConnectionId == serverCids.at(secondClientAddress) ||
            serverConnectionId == serverCids.at(thirdClientAddress));
      });
  shutdownServerAndClients(server, firstClient, secondClient, thirdClient);
}

TEST_F(QuicServerMigrationIntegrationTest, TestMigrateOnlyASubsetOfTheTransports) {
  // Server variables.
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  folly::SocketAddress serverMigrationAddress("127.0.1.1", 6000);
  QuicIPAddress quicIpServerMigrationAddress(serverMigrationAddress);
  ASSERT_NE(serverMigrationAddress, folly::SocketAddress(serverIP, serverPort));

  auto clientStateUpdateCallback =
      std::make_shared<StrictMock<MockClientStateUpdateCallback>>();
  auto serverMigrationEventCallbackServerSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  std::unordered_map<folly::SocketAddress, ConnectionId> serverCids;

  // Client variables.
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  folly::SocketAddress firstClientAddress =
      folly::SocketAddress("127.1.1.1", 50001);
  folly::SocketAddress secondClientAddress =
      folly::SocketAddress("127.2.2.2", 50002);
  folly::SocketAddress thirdClientAddress =
      folly::SocketAddress("127.3.3.3", 50003);

  auto serverMigrationEventCallbackFirstClient =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackSecondClient =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackThirdClient =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();

  // First step: connect all the clients (sequentially for simplicity).
  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(3))
      .WillRepeatedly(
          [&](folly::SocketAddress clientAddress,
              ConnectionId serverConnectionId,
              folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                  negotiatedProtocols) {
            EXPECT_TRUE(
                clientAddress == firstClientAddress ||
                clientAddress == secondClientAddress ||
                clientAddress == thirdClientAddress);
            ASSERT_TRUE(negotiatedProtocols.has_value());
            EXPECT_EQ(negotiatedProtocols->size(), 1);
            EXPECT_TRUE(
                negotiatedProtocols->count(ServerMigrationProtocol::EXPLICIT));
            std::vector<uint8_t> connId(
                serverConnectionId.data(),
                serverConnectionId.data() + serverConnectionId.size());
            serverCids.emplace(clientAddress, ConnectionId{connId});
          });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback,
      serverMigrationEventCallbackServerSide);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient firstClient(
      firstClientAddress.getAddressStr(),
      firstClientAddress.getPort(),
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackFirstClient);
  startClientAndWaitUntilHandshakeFinished(firstClient, defaultTestPredicate);

  QuicServerMigrationIntegrationTestClient secondClient(
      secondClientAddress.getAddressStr(),
      secondClientAddress.getPort(),
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackSecondClient);
  startClientAndWaitUntilHandshakeFinished(
      secondClient, serverMigratedAbruptlyTestPredicate);

  QuicServerMigrationIntegrationTestClient thirdClient(
      thirdClientAddress.getAddressStr(),
      thirdClientAddress.getPort(),
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackThirdClient);
  startClientAndWaitUntilHandshakeFinished(
      thirdClient, serverMigratedAbruptlyTestPredicate);
  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());

  // Second step: notify imminent server migration only to the transport
  // managing the first client. The other two transports should close the
  // connection.
  folly::fibers::Baton serverMigrationReadyBaton;
  std::atomic<int> nServerTransportsReady = 0;
  QuicServer::ServerMigrationSettings migrationSettings;
  migrationSettings[serverCids.at(firstClientAddress)] = std::make_pair(
      ServerMigrationProtocol::EXPLICIT, quicIpServerMigrationAddress);

  EXPECT_CALL(
      *serverMigrationEventCallbackFirstClient, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        EXPECT_EQ(frame, ServerMigrationFrame(quicIpServerMigrationAddress));
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackSecondClient, onServerMigrationReceived)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackThirdClient, onServerMigrationReceived)
      .Times(0);

  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose)
      .Times(Exactly(2))
      .WillRepeatedly([&](ConnectionId serverConnectionId) {
        EXPECT_TRUE(
            serverConnectionId == serverCids.at(secondClientAddress) ||
            serverConnectionId == serverCids.at(thirdClientAddress));
        ++nServerTransportsReady;
        if (nServerTransportsReady == 3) {
          serverMigrationReadyBaton.post();
        }
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationAckReceived)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId,
                    ServerMigrationFrame frame) {
        EXPECT_EQ(serverConnectionId, serverCids.at(firstClientAddress));
        EXPECT_EQ(frame, ServerMigrationFrame(quicIpServerMigrationAddress));
      });
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationReady)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId, serverCids.at(firstClientAddress));
        ++nServerTransportsReady;
        if (nServerTransportsReady == 3) {
          serverMigrationReadyBaton.post();
        }
      });

  server.server->onImminentServerMigration(migrationSettings);
  EXPECT_TRUE(serverMigrationReadyBaton.try_wait_for(batonTimeout));
  serverMigrationReadyBaton.reset();
  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackFirstClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackSecondClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackThirdClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Third step: start the server migration.
  folly::fibers::Baton serverMigrationCompletedBaton;

  EXPECT_CALL(
      *serverMigrationEventCallbackFirstClient, onServerMigrationProbingStarted)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationProtocol protocol,
                    folly::SocketAddress probingAddress) {
        EXPECT_EQ(protocol, ServerMigrationProtocol::EXPLICIT);
        EXPECT_EQ(probingAddress, serverMigrationAddress);
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackFirstClient, onServerMigrationCompleted())
      .Times(Exactly(1));

  EXPECT_CALL(
      *serverMigrationEventCallbackSecondClient,
      onServerMigrationProbingStarted)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackSecondClient, onServerMigrationCompleted())
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackThirdClient, onServerMigrationProbingStarted)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackThirdClient, onServerMigrationCompleted())
      .Times(0);

  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationCompleted(_))
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId, serverCids.at(firstClientAddress));
        serverMigrationCompletedBaton.post();
      });

  server.server->onNetworkSwitch(serverMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), serverMigrationAddress);

  // Send a message from the first client, so that it
  // detects the loss and starts probing.
  firstClient.send("probing");

  EXPECT_TRUE(serverMigrationCompletedBaton.try_wait_for(batonTimeout));
  serverMigrationCompletedBaton.reset();
  EXPECT_TRUE(firstClient.messageReceived.try_wait_for(batonTimeout));
  firstClient.messageReceived.reset();

  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackFirstClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackSecondClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackThirdClient.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Last step: close the connection involving the first client.
  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose)
      .Times(Exactly(1))
      .WillRepeatedly([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId, serverCids.at(firstClientAddress));
      });
  shutdownServerAndClients(server, firstClient, secondClient, thirdClient);
}

TEST_F(QuicServerMigrationIntegrationTest, TestSequenceOfMigrationsWithDifferentProtocols) {
  // Migration addresses.
  folly::SocketAddress firstServerMigrationAddress("127.0.1.1", 6000);
  QuicIPAddress firstQuicIpServerMigrationAddress(firstServerMigrationAddress);

  folly::SocketAddress secondServerMigrationAddress("127.0.2.2", 7000);
  QuicIPAddress secondQuicIpServerMigrationAddress(
      secondServerMigrationAddress);

  folly::SocketAddress thirdServerMigrationAddress("127.0.3.3", 8000);
  QuicIPAddress thirdQuicIpServerMigrationAddress(thirdServerMigrationAddress);
  ASSERT_NE(
      firstServerMigrationAddress, folly::SocketAddress(serverIP, serverPort));

  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  serverSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
  std::string serverCidHex;

  auto clientStateUpdateCallback =
      std::make_shared<StrictMock<MockClientStateUpdateCallback>>();
  auto serverMigrationEventCallbackServerSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackClientSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();

  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](folly::SocketAddress clientAddress,
                    ConnectionId serverConnectionId,
                    folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                        negotiatedProtocols) {
        EXPECT_EQ(clientAddress, folly::SocketAddress(clientIP, clientPort));
        ASSERT_TRUE(negotiatedProtocols.has_value());
        EXPECT_EQ(negotiatedProtocols->size(), 3);
        EXPECT_TRUE(
            negotiatedProtocols->count(ServerMigrationProtocol::EXPLICIT));
        EXPECT_TRUE(
            negotiatedProtocols->count(ServerMigrationProtocol::SYMMETRIC));
        EXPECT_TRUE(negotiatedProtocols->count(
            ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC));
        serverCidHex = serverConnectionId.hex();
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback,
      serverMigrationEventCallbackServerSide);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackClientSide);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);
  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());

  // Notify the first imminent server migration using the Explicit protocol.
  folly::fibers::Baton serverMigrationReadyBaton;

  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        EXPECT_EQ(
            frame, ServerMigrationFrame(firstQuicIpServerMigrationAddress));
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationAckReceived)
      .Times(Exactly(1))
      .WillOnce(
          [&](ConnectionId serverConnectionId, ServerMigrationFrame frame) {
            EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
            EXPECT_EQ(
                frame, ServerMigrationFrame(firstQuicIpServerMigrationAddress));
          });
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationReady)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationReadyBaton.post();
      });

  server.server->onImminentServerMigration(
      ServerMigrationProtocol::EXPLICIT, firstQuicIpServerMigrationAddress);
  EXPECT_TRUE(serverMigrationReadyBaton.try_wait_for(batonTimeout));
  serverMigrationReadyBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Start the first migration.
  folly::fibers::Baton serverMigrationCompletedBaton;
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationProbingStarted)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationProtocol protocol,
                    folly::SocketAddress probingAddress) {
        EXPECT_EQ(protocol, ServerMigrationProtocol::EXPLICIT);
        EXPECT_EQ(probingAddress, firstServerMigrationAddress);
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationCompleted())
      .Times(Exactly(1));
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationCompleted(_))
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationCompletedBaton.post();
      });

  server.server->onNetworkSwitch(firstServerMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), firstServerMigrationAddress);
  client.send("probing");
  EXPECT_TRUE(serverMigrationCompletedBaton.try_wait_for(batonTimeout));
  serverMigrationCompletedBaton.reset();
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Notify the second imminent server migration using the Symmetric protocol.
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationReady)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationReadyBaton.post();
      });

  server.server->onImminentServerMigration(
      ServerMigrationProtocol::SYMMETRIC, folly::none);
  EXPECT_TRUE(serverMigrationReadyBaton.try_wait_for(batonTimeout));
  serverMigrationReadyBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Start the second migration.
  EXPECT_CALL(*serverMigrationEventCallbackClientSide, onServerMigratedReceived)
      .Times(AtMost(1));
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationCompleted())
      .Times(Exactly(1));
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigratedAckReceived)
      .Times(AtMost(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationCompleted(_))
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationCompletedBaton.post();
      });

  server.server->onNetworkSwitch(secondServerMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), secondServerMigrationAddress);
  EXPECT_TRUE(serverMigrationCompletedBaton.try_wait_for(batonTimeout));
  serverMigrationCompletedBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Test reachability.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  // Notify the third imminent server migration using
  // the Synchronized Symmetric protocol.
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        QuicIPAddress emptyAddress;
        EXPECT_EQ(frame, ServerMigrationFrame(emptyAddress));
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationAckReceived)
      .Times(Exactly(1))
      .WillOnce(
          [&](ConnectionId serverConnectionId, ServerMigrationFrame frame) {
            QuicIPAddress emptyAddress;
            EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
            EXPECT_EQ(frame, ServerMigrationFrame(emptyAddress));
          });
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationReady)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationReadyBaton.post();
      });

  server.server->onImminentServerMigration(
      ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC, folly::none);
  EXPECT_TRUE(serverMigrationReadyBaton.try_wait_for(batonTimeout));
  serverMigrationReadyBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Start the migration.
  EXPECT_CALL(*serverMigrationEventCallbackClientSide, onServerMigratedReceived)
      .Times(AtMost(1));
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationCompleted())
      .Times(Exactly(1));
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigratedAckReceived)
      .Times(AtMost(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationCompleted(_))
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationCompletedBaton.post();
      });

  server.server->onNetworkSwitch(thirdServerMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), thirdServerMigrationAddress);
  EXPECT_TRUE(serverMigrationCompletedBaton.try_wait_for(batonTimeout));
  serverMigrationCompletedBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Test reachability.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  // Close the connection.
  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
      });
  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestSequenceOfPoolOfAddressesMigrations) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.1"), 1234));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.2"), 4567));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.3"), 8910));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::SocketAddress(serverIP, serverPort)));
  std::string serverCidHex;

  // Migration addresses. The second one simulates a
  // come back to the original server address.
  folly::SocketAddress firstServerMigrationAddress("127.1.1.3", 8910);
  folly::SocketAddress secondServerMigrationAddress(serverIP, serverPort);
  ASSERT_NE(
      firstServerMigrationAddress, folly::SocketAddress(serverIP, serverPort));

  auto clientStateUpdateCallback =
      std::make_shared<StrictMock<MockClientStateUpdateCallback>>();
  auto serverMigrationEventCallbackServerSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackClientSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();

  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](folly::SocketAddress clientAddress,
                    ConnectionId serverConnectionId,
                    folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                        negotiatedProtocols) {
        EXPECT_EQ(clientAddress, folly::SocketAddress(clientIP, clientPort));
        ASSERT_TRUE(negotiatedProtocols.has_value());
        EXPECT_EQ(negotiatedProtocols->size(), 1);
        EXPECT_TRUE(negotiatedProtocols->count(
            ServerMigrationProtocol::POOL_OF_ADDRESSES));
        serverCidHex = serverConnectionId.hex();
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onPoolMigrationAddressReceived)
      .Times(Exactly(poolMigrationAddresses.size()))
      .WillRepeatedly([&](PoolMigrationAddressFrame frame) {
        auto it = poolMigrationAddresses.find(frame.address);
        EXPECT_NE(it, poolMigrationAddresses.end());
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide,
      onPoolMigrationAddressAckReceived)
      .Times(Exactly(poolMigrationAddresses.size()))
      .WillRepeatedly([&](ConnectionId serverConnectionId,
                          PoolMigrationAddressFrame frame) {
        EXPECT_EQ(serverCidHex, serverConnectionId.hex());
        auto it = poolMigrationAddresses.find(frame.address);
        EXPECT_NE(it, poolMigrationAddresses.end());
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback,
      serverMigrationEventCallbackServerSide,
      poolMigrationAddresses);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackClientSide);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);

  // Send a message after the handshake is finished, to be sure that the
  // acknowledgements for the POOL_MIGRATION_ADDRESS frames are received
  // by the server.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Before starting the migration, wait a bit to be sure that the ACK for the
  // echo message is received by the server. This avoids a particular case where
  // the call to onNetworkSwitch() happens before the server receives this ACK,
  // causing a PTO in the server just after the migration. Due to the PTO, the
  // server sends a PING message from the new address, right in the middle of
  // the migration probing done by the client, concluding it and forcing the
  // client to send a PATH_CHALLENGE. This behaviour is correct and satisfies
  // the requirements of the Pool of Addresses protocol, but "hides" the
  // migration probing in the network traces, so it is better to avoid it in
  // this context. Note that the test still succeeds if the wait is removed.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // Notify the first imminent server migration.
  folly::fibers::Baton serverMigrationReadyBaton;
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationReady)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationReadyBaton.post();
      });

  server.server->onImminentServerMigration(
      ServerMigrationProtocol::POOL_OF_ADDRESSES, folly::none);
  EXPECT_TRUE(serverMigrationReadyBaton.try_wait_for(batonTimeout));
  serverMigrationReadyBaton.reset();
  Mock::VerifyAndClearExpectations(&serverMigrationEventCallbackServerSide);

  // Start the first migration.
  folly::fibers::Baton serverMigrationCompletedBaton;
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationProbingStarted)
      .Times(AtLeast(1))
      .WillRepeatedly([&](ServerMigrationProtocol protocol,
                          folly::SocketAddress probingAddress) {
        EXPECT_EQ(protocol, ServerMigrationProtocol::POOL_OF_ADDRESSES);
        auto it = poolMigrationAddresses.find(QuicIPAddress(probingAddress));
        EXPECT_TRUE(
            it != poolMigrationAddresses.end() ||
            probingAddress == folly::SocketAddress(serverIP, serverPort));
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationCompleted())
      .Times(Exactly(1));
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationCompleted(_))
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationCompletedBaton.post();
      });

  server.server->onNetworkSwitch(firstServerMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), firstServerMigrationAddress);
  client.send("probing");
  EXPECT_TRUE(serverMigrationCompletedBaton.try_wait_for(batonTimeout));
  serverMigrationCompletedBaton.reset();
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();
  Mock::VerifyAndClearExpectations(&serverMigrationEventCallbackClientSide);
  Mock::VerifyAndClearExpectations(&serverMigrationEventCallbackServerSide);

  // Test reachability.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  // Notify the second imminent server migration. Again wait for some time
  // to clear a possible pending PTO and produce better network traces.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationReady)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationReadyBaton.post();
      });

  server.server->onImminentServerMigration(
      ServerMigrationProtocol::POOL_OF_ADDRESSES, folly::none);
  EXPECT_TRUE(serverMigrationReadyBaton.try_wait_for(batonTimeout));
  serverMigrationReadyBaton.reset();
  Mock::VerifyAndClearExpectations(&serverMigrationEventCallbackServerSide);

  // Start the second migration.
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationProbingStarted)
      .Times(AtLeast(1))
      .WillRepeatedly([&](ServerMigrationProtocol protocol,
                          folly::SocketAddress probingAddress) {
        EXPECT_EQ(protocol, ServerMigrationProtocol::POOL_OF_ADDRESSES);
        auto it = poolMigrationAddresses.find(QuicIPAddress(probingAddress));
        EXPECT_TRUE(
            it != poolMigrationAddresses.end() ||
            probingAddress == firstServerMigrationAddress);
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationCompleted())
      .Times(Exactly(1));
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationCompleted(_))
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationCompletedBaton.post();
      });

  server.server->onNetworkSwitch(secondServerMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), secondServerMigrationAddress);
  client.send("probing");
  EXPECT_TRUE(serverMigrationCompletedBaton.try_wait_for(batonTimeout));
  serverMigrationCompletedBaton.reset();
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();
  Mock::VerifyAndClearExpectations(&serverMigrationEventCallbackClientSide);
  Mock::VerifyAndClearExpectations(&serverMigrationEventCallbackServerSide);

  // Test reachability.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  // Close the connection.
  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
      });
  shutdownServerAndClients(server, client);
}

TEST_F(QuicServerMigrationIntegrationTest, TestConcurrentClientAndServerMigrations) {
  // Migration addresses.
  folly::SocketAddress serverMigrationAddress("127.0.1.1", 6000);
  QuicIPAddress quicIpServerMigrationAddress(serverMigrationAddress);
  folly::SocketAddress clientMigrationAddress("127.0.0.100", 7000);
  ASSERT_NE(serverMigrationAddress, folly::SocketAddress(serverIP, serverPort));
  ASSERT_NE(clientMigrationAddress, folly::SocketAddress(clientIP, clientPort));

  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  std::string serverCidHex;

  auto clientStateUpdateCallback =
      std::make_shared<StrictMock<MockClientStateUpdateCallback>>();
  auto serverMigrationEventCallbackServerSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();
  auto serverMigrationEventCallbackClientSide =
      std::make_shared<StrictMock<MockServerMigrationEventCallback>>();

  EXPECT_CALL(*clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce([&](folly::SocketAddress clientAddress,
                    ConnectionId serverConnectionId,
                    folly::Optional<std::unordered_set<ServerMigrationProtocol>>
                        negotiatedProtocols) {
        EXPECT_EQ(clientAddress, folly::SocketAddress(clientIP, clientPort));
        ASSERT_TRUE(negotiatedProtocols.has_value());
        EXPECT_EQ(negotiatedProtocols->size(), 1);
        EXPECT_TRUE(
            negotiatedProtocols->count(ServerMigrationProtocol::EXPLICIT));
        serverCidHex = serverConnectionId.hex();
      });

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      clientStateUpdateCallback,
      serverMigrationEventCallbackServerSide);
  startServerAndWaitUntilInitialized(server);

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      serverMigrationEventCallbackClientSide);
  startClientAndWaitUntilHandshakeFinished(client, defaultTestPredicate);
  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());

  // Notify imminent server migration.
  folly::fibers::Baton serverMigrationReadyBaton;
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationReceived)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationFrame frame) {
        EXPECT_EQ(frame, ServerMigrationFrame(quicIpServerMigrationAddress));
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationAckReceived)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId,
                    ServerMigrationFrame frame) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        EXPECT_EQ(frame, ServerMigrationFrame(quicIpServerMigrationAddress));
      });
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationReady)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationReadyBaton.post();
      });

  server.server->onImminentServerMigration(
      ServerMigrationProtocol::EXPLICIT, quicIpServerMigrationAddress);
  EXPECT_TRUE(serverMigrationReadyBaton.try_wait_for(batonTimeout));
  serverMigrationReadyBaton.reset();
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());

  // Start both the client and server migrations.
  folly::fibers::Baton serverMigrationCompletedBaton;
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationProbingStarted)
      .Times(Exactly(1))
      .WillOnce([&](ServerMigrationProtocol protocol,
                    folly::SocketAddress probingAddress) {
        EXPECT_EQ(protocol, ServerMigrationProtocol::EXPLICIT);
        EXPECT_EQ(probingAddress, serverMigrationAddress);
      });
  EXPECT_CALL(
      *serverMigrationEventCallbackClientSide, onServerMigrationCompleted())
      .Times(Exactly(1));
  EXPECT_CALL(*serverMigrationEventCallbackServerSide, onServerMigrationFailed)
      .Times(0);
  EXPECT_CALL(
      *serverMigrationEventCallbackServerSide, onServerMigrationCompleted(_))
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
        serverMigrationCompletedBaton.post();
      });
  EXPECT_CALL(*clientStateUpdateCallback, onClientMigrationDetected)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId,
                    folly::SocketAddress newClientAddress) {
        EXPECT_EQ(serverCidHex, serverConnectionId.hex());
        EXPECT_EQ(clientMigrationAddress, newClientAddress);
      });

  server.server->onNetworkSwitch(serverMigrationAddress);
  EXPECT_EQ(server.server->getAddress(), serverMigrationAddress);

  auto newClientSocket =
      std::make_unique<folly::AsyncUDPSocket>(client.transport->getEventBase());
  newClientSocket->bind(clientMigrationAddress);
  client.transport->onNetworkSwitch(std::move(newClientSocket));

  client.send("probing");
  EXPECT_TRUE(serverMigrationCompletedBaton.try_wait_for(batonTimeout));
  serverMigrationCompletedBaton.reset();
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackClientSide.get());
  Mock::VerifyAndClearExpectations(
      serverMigrationEventCallbackServerSide.get());
  Mock::VerifyAndClearExpectations(clientStateUpdateCallback.get());

  // Test reachability.
  client.send("ping");
  EXPECT_TRUE(client.messageReceived.try_wait_for(batonTimeout));
  client.messageReceived.reset();

  // Close the connection.
  EXPECT_CALL(*clientStateUpdateCallback, onConnectionClose)
      .Times(Exactly(1))
      .WillOnce([&](ConnectionId serverConnectionId) {
        EXPECT_EQ(serverConnectionId.hex(), serverCidHex);
      });
  shutdownServerAndClients(server, client);
}

} // namespace test
} // namespace quic
