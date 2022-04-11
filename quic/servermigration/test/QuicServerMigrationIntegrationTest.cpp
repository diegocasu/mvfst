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
      std::unordered_set<ServerMigrationProtocol> migrationProtocols)
      : clientHost(std::move(clientHost)),
        clientPort(clientPort),
        serverHost(std::move(serverHost)),
        serverPort(serverPort),
        migrationProtocols(std::move(migrationProtocols)) {}

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

      transport->allowServerMigration(migrationProtocols);
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
    ServerTransportFactory() = default;

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
      handler->setQuicSocket(transport);
      handlers.push_back(std::move(handler));
      return transport;
    }

    std::vector<std::unique_ptr<MessageHandler>> handlers;
  };

  QuicServerMigrationIntegrationTestServer(
      std::string host,
      uint16_t port,
      std::unordered_set<ServerMigrationProtocol> migrationProtocols,
      ClientStateUpdateCallback* clientStateCallback)
      : host(std::move(host)),
        port(port),
        server(QuicServer::createQuicServer()),
        migrationProtocols(std::move(migrationProtocols)) {
    server->setQuicServerTransportFactory(
        std::make_unique<ServerTransportFactory>());

    auto serverCtx = quic::test::createServerCtx();
    serverCtx->setClock(std::make_shared<fizz::SystemClock>());
    server->setFizzContext(serverCtx);

    TransportSettings settings;
    settings.disableMigration = false;
    server->setTransportSettings(settings);

    server->allowServerMigration(this->migrationProtocols);
    server->setClientStateUpdateCallback(clientStateCallback);
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
  std::unordered_set<ServerMigrationProtocol> migrationProtocols;
};

} // namespace test
} // namespace quic
