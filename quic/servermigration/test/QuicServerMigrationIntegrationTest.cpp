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
      ServerMigrationEventCallback* serverMigrationEventCallback = nullptr)
      : clientHost(std::move(clientHost)),
        clientPort(clientPort),
        serverHost(std::move(serverHost)),
        serverPort(serverPort),
        migrationProtocols(std::move(migrationProtocols)),
        serverMigrationEventCallback(serverMigrationEventCallback) {}

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

  void start() {
    auto evb = networkThread.getEventBase();

    evb->runInEventBaseThreadAndWait([&] {
      folly::SocketAddress clientAddress(clientHost.c_str(), clientPort);
      auto sock = std::make_unique<folly::AsyncUDPSocket>(evb);
      sock->bind(clientAddress);

      auto fizzClientContext =
          FizzClientQuicHandshakeContext::Builder()
              .setCertificateVerifier(test::createTestCertificateVerifier())
              .build();

      transport = std::make_shared<quic::QuicClientTransport>(
          evb, std::move(sock), std::move(fizzClientContext), 8);

      folly::SocketAddress serverAddress(serverHost.c_str(), serverPort);
      transport->addNewPeerAddress(serverAddress);

      TransportSettings settings;
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

  std::string clientHost;
  uint16_t clientPort;
  std::string serverHost;
  uint16_t serverPort;
  std::shared_ptr<quic::QuicClientTransport> transport;
  folly::ScopedEventBaseThread networkThread;
  std::unordered_set<ServerMigrationProtocol> migrationProtocols;
  ServerMigrationEventCallback* serverMigrationEventCallback{nullptr};

  // Synchronization variables.
  folly::fibers::Baton startDone_;
  folly::fibers::Baton messageReceived;

  // Maps used to read/write messages.
  std::map<quic::StreamId, BufQueue> pendingOutput_;
  std::map<quic::StreamId, uint64_t> recvOffsets_;
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
        ClientStateUpdateCallback* clientStateCallback,
        ServerMigrationEventCallback* serverMigrationEventCallback)
        : migrationProtocols(std::move(migrationProtocols)),
          poolMigrationAddresses(std::move(poolMigrationAddresses)),
          clientStateCallback(clientStateCallback),
          serverMigrationEventCallback(serverMigrationEventCallback){};

    ~ServerTransportFactory() override {
      while (!handlers.empty()) {
        auto& handler = handlers.back();
        handler->evb->runImmediatelyOrRunInEventBaseThreadAndWait(
            [this] { handlers.pop_back(); });
      }
    }

    quic::QuicServerTransport::Ptr make(
        folly::EventBase* evb,
        std::unique_ptr<folly::AsyncUDPSocket> sock,
        const folly::SocketAddress&,
        QuicVersion,
        std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept
        override {
      CHECK_EQ(evb, sock->getEventBase());
      auto handler = std::make_unique<MessageHandler>(evb);
      auto transport = quic::QuicServerTransport::make(
          evb, std::move(sock), handler.get(), handler.get(), ctx);

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
      handlers.push_back(std::move(handler));
      return transport;
    }

    std::vector<std::unique_ptr<MessageHandler>> handlers;
    std::unordered_set<ServerMigrationProtocol> migrationProtocols;
    std::unordered_set<QuicIPAddress, QuicIPAddressHash> poolMigrationAddresses;
    ClientStateUpdateCallback* clientStateCallback{nullptr};
    ServerMigrationEventCallback* serverMigrationEventCallback{nullptr};
  };

  QuicServerMigrationIntegrationTestServer(
      std::string host,
      uint16_t port,
      std::unordered_set<ServerMigrationProtocol> migrationProtocols,
      ClientStateUpdateCallback* clientStateCallback = nullptr,
      ServerMigrationEventCallback* serverMigrationEventCallback = nullptr,
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
            clientStateCallback,
            serverMigrationEventCallback));

    auto serverCtx = quic::test::createServerCtx();
    serverCtx->setClock(std::make_shared<fizz::SystemClock>());
    server->setFizzContext(serverCtx);

    TransportSettings settings;
    settings.disableMigration = false;
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
 public:
  std::string serverIP{"127.0.0.1"};
  uint16_t serverPort{50000};
  std::string clientIP{"127.0.0.55"};
  uint16_t clientPort{50001};
  std::unordered_set<ServerMigrationProtocol> serverSupportedProtocols;
  std::unordered_set<ServerMigrationProtocol> clientSupportedProtocols;
  std::unordered_set<QuicIPAddress, QuicIPAddressHash> poolMigrationAddresses;
};

TEST_F(QuicServerMigrationIntegrationTest, TestNewClientNotified) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  clientSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);

  auto compareWithExpectedClient =
      [&](folly::SocketAddress clientAddress,
          Unused,
          folly::Optional<std::unordered_set<ServerMigrationProtocol>>
              negotiatedProtocols) {
        EXPECT_EQ(clientAddress.getIPAddress().str(), clientIP);
        EXPECT_EQ(clientAddress.getPort(), clientPort);

        EXPECT_TRUE(negotiatedProtocols.has_value());
        EXPECT_EQ(negotiatedProtocols.value().size(), 1);
        EXPECT_TRUE(negotiatedProtocols.value().count(
            ServerMigrationProtocol::EXPLICIT));
      };

  MockClientStateUpdateCallback clientStateUpdateCallback;
  EXPECT_CALL(clientStateUpdateCallback, onHandshakeFinished)
      .Times(Exactly(1))
      .WillOnce(compareWithExpectedClient);

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      &clientStateUpdateCallback);
  server.start();
  server.server->waitUntilInitialized();

  QuicServerMigrationIntegrationTestClient client(
      clientIP, clientPort, serverIP, serverPort, clientSupportedProtocols);
  client.start();
  client.startDone_.wait();

  // Send a message and wait for the response to be sure that
  // the server has finished the handshake.
  client.send("ping");
  client.messageReceived.wait();

  // When the response to the previous message has been received,
  // clientStateUpdateCallback should have been evaluated, so the test can end.
  client.close();
  server.server->shutdown();
}

TEST_F(QuicServerMigrationIntegrationTest, TestConnectionCloseNotified) {
  std::string serverCidHex;
  MockClientStateUpdateCallback clientStateUpdateCallback;

  {
    InSequence seq;
    EXPECT_CALL(clientStateUpdateCallback, onHandshakeFinished)
        .Times(Exactly(1))
        .WillOnce([&](Unused, ConnectionId serverConnectionId, Unused) {
          serverCidHex = serverConnectionId.hex();
        });
    EXPECT_CALL(clientStateUpdateCallback, onConnectionClose)
        .Times(Exactly(1))
        .WillOnce([&](ConnectionId serverConnectionId) {
          EXPECT_EQ(serverCidHex, serverConnectionId.hex());
        });
  }

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      &clientStateUpdateCallback);
  server.start();
  server.server->waitUntilInitialized();

  QuicServerMigrationIntegrationTestClient client(
      clientIP, clientPort, serverIP, serverPort, clientSupportedProtocols);
  client.start();
  client.startDone_.wait();

  client.send("ping");
  client.messageReceived.wait();

  client.close();
  server.server->shutdown();
}

TEST_F(QuicServerMigrationIntegrationTest, TestClientMigrationNotified) {
  folly::SocketAddress clientMigrationAddress("127.0.1.1", 50000);
  ASSERT_NE(clientMigrationAddress.getIPAddress().str(), clientIP);

  std::string serverCidHex;
  MockClientStateUpdateCallback clientStateUpdateCallback;

  {
    InSequence seq;
    EXPECT_CALL(clientStateUpdateCallback, onHandshakeFinished)
        .Times(Exactly(1))
        .WillOnce([&](Unused, ConnectionId serverConnectionId, Unused) {
          serverCidHex = serverConnectionId.hex();
        });
    EXPECT_CALL(clientStateUpdateCallback, onMigrationDetected)
        .Times(Exactly(1))
        .WillOnce([&](ConnectionId serverConnectionId,
                      folly::SocketAddress newClientAddress) {
          EXPECT_EQ(serverCidHex, serverConnectionId.hex());
          EXPECT_EQ(clientMigrationAddress, newClientAddress);
        });
  }

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      &clientStateUpdateCallback);
  server.start();
  server.server->waitUntilInitialized();

  QuicServerMigrationIntegrationTestClient client(
      clientIP, clientPort, serverIP, serverPort, clientSupportedProtocols);
  client.start();
  client.startDone_.wait();

  client.send("ping");
  client.messageReceived.wait();
  client.messageReceived.reset();

  // Migrate client.
  auto newClientSocket =
      std::make_unique<folly::AsyncUDPSocket>(client.transport->getEventBase());
  newClientSocket->bind(clientMigrationAddress);
  client.transport->onNetworkSwitch(std::move(newClientSocket));

  // Send a message from the new address.
  client.send("ping");
  client.messageReceived.wait();

  client.close();
  server.server->shutdown();
}

TEST_F(QuicServerMigrationIntegrationTest, TestSuccessfulNegotiation) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  serverSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);

  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  clientSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);

  MockClientStateUpdateCallback clientStateUpdateCallback;
  EXPECT_CALL(clientStateUpdateCallback, onHandshakeFinished)
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
      &clientStateUpdateCallback);
  server.start();
  server.server->waitUntilInitialized();

  QuicServerMigrationIntegrationTestClient client(
      clientIP, clientPort, serverIP, serverPort, clientSupportedProtocols);
  client.start();
  client.startDone_.wait();

  client.send("ping");
  client.messageReceived.wait();

  client.close();
  server.server->shutdown();
}

TEST_F(QuicServerMigrationIntegrationTest, TestUnsuccessfulNegotiation) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);

  clientSupportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);

  MockClientStateUpdateCallback clientStateUpdateCallback;
  EXPECT_CALL(clientStateUpdateCallback, onHandshakeFinished)
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
      &clientStateUpdateCallback);
  server.start();
  server.server->waitUntilInitialized();

  QuicServerMigrationIntegrationTestClient client(
      clientIP, clientPort, serverIP, serverPort, clientSupportedProtocols);
  client.start();
  client.startDone_.wait();

  client.send("ping");
  client.messageReceived.wait();

  client.close();
  server.server->shutdown();
}

TEST_F(QuicServerMigrationIntegrationTest, TestNoNegotiation) {
  // serverSupportedProtocols and clientSupportedProtocols are left empty,
  // so the server migration support is automatically disabled
  // by the test classes.

  MockClientStateUpdateCallback clientStateUpdateCallback;
  EXPECT_CALL(clientStateUpdateCallback, onHandshakeFinished)
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
      &clientStateUpdateCallback);
  server.start();
  server.server->waitUntilInitialized();

  QuicServerMigrationIntegrationTestClient client(
      clientIP, clientPort, serverIP, serverPort, clientSupportedProtocols);
  client.start();
  client.startDone_.wait();

  client.send("ping");
  client.messageReceived.wait();

  client.close();
  server.server->shutdown();
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
  MockClientStateUpdateCallback clientStateUpdateCallback;
  MockServerMigrationEventCallback serverMigrationEventCallbackServerSide;
  MockServerMigrationEventCallback serverMigrationEventCallbackClientSide;

  EXPECT_CALL(clientStateUpdateCallback, onHandshakeFinished)
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
      serverMigrationEventCallbackClientSide, onPoolMigrationAddressReceived)
      .Times(Exactly(poolMigrationAddresses.size()))
      .WillRepeatedly([&](PoolMigrationAddressFrame frame) {
        auto it = poolMigrationAddresses.find(frame.address);
        EXPECT_NE(it, poolMigrationAddresses.end());
      });
  EXPECT_CALL(
      serverMigrationEventCallbackServerSide, onPoolMigrationAddressAckReceived)
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
      &clientStateUpdateCallback,
      &serverMigrationEventCallbackServerSide,
      poolMigrationAddresses);
  server.start();
  server.server->waitUntilInitialized();

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      &serverMigrationEventCallbackClientSide);
  client.start();
  client.startDone_.wait();

  client.send("ping");
  client.messageReceived.wait();

  client.close();
  server.server->shutdown();
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

  MockServerMigrationEventCallback serverMigrationEventCallbackServerSide;
  MockServerMigrationEventCallback serverMigrationEventCallbackClientSide;

  EXPECT_CALL(
      serverMigrationEventCallbackClientSide, onPoolMigrationAddressReceived)
      .Times(0);
  EXPECT_CALL(
      serverMigrationEventCallbackServerSide, onPoolMigrationAddressAckReceived)
      .Times(0);

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      nullptr,
      &serverMigrationEventCallbackServerSide,
      poolMigrationAddresses);
  server.start();
  server.server->waitUntilInitialized();

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      &serverMigrationEventCallbackClientSide);
  client.start();
  client.startDone_.wait();

  client.send("ping");
  client.messageReceived.wait();

  client.close();
  server.server->shutdown();
}

TEST_F(QuicServerMigrationIntegrationTest, TestPoolMigrationAddressesWithNoNegotiation) {
  serverSupportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.1"), 1234));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.2"), 4567));
  poolMigrationAddresses.insert(
      QuicIPAddress(folly::IPAddressV4("127.1.1.3"), 8910));

  MockServerMigrationEventCallback serverMigrationEventCallbackServerSide;
  MockServerMigrationEventCallback serverMigrationEventCallbackClientSide;

  EXPECT_CALL(
      serverMigrationEventCallbackClientSide, onPoolMigrationAddressReceived)
      .Times(0);
  EXPECT_CALL(
      serverMigrationEventCallbackServerSide, onPoolMigrationAddressAckReceived)
      .Times(0);

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      nullptr,
      &serverMigrationEventCallbackServerSide,
      poolMigrationAddresses);
  server.start();
  server.server->waitUntilInitialized();

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      &serverMigrationEventCallbackClientSide);
  client.start();
  client.startDone_.wait();

  client.send("ping");
  client.messageReceived.wait();

  client.close();
  server.server->shutdown();
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

  MockServerMigrationEventCallback serverMigrationEventCallbackServerSide;
  MockServerMigrationEventCallback serverMigrationEventCallbackClientSide;

  EXPECT_CALL(
      serverMigrationEventCallbackClientSide, onPoolMigrationAddressReceived)
      .Times(0);
  EXPECT_CALL(
      serverMigrationEventCallbackServerSide, onPoolMigrationAddressAckReceived)
      .Times(0);

  QuicServerMigrationIntegrationTestServer server(
      serverIP,
      serverPort,
      serverSupportedProtocols,
      nullptr,
      &serverMigrationEventCallbackServerSide,
      poolMigrationAddresses);
  server.start();
  server.server->waitUntilInitialized();

  QuicServerMigrationIntegrationTestClient client(
      clientIP,
      clientPort,
      serverIP,
      serverPort,
      clientSupportedProtocols,
      &serverMigrationEventCallbackClientSide);
  client.start();
  client.startDone_.wait();

  client.send("ping");
  client.messageReceived.wait();

  client.close();
  server.server->shutdown();
}

} // namespace test
} // namespace quic
