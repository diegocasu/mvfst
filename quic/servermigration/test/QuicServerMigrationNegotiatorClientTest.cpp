#include <folly/portability/GTest.h>
#include <quic/servermigration/QuicServerMigrationNegotiatorClient.h>

namespace quic {
namespace test {

TEST(QuicServerMigrationNegotiatorClientTest, TestEmptySupportedProtocols) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  ASSERT_TRUE(supportedProtocols.empty());
  EXPECT_THROW(
      QuicServerMigrationNegotiatorClient negotiator(supportedProtocols),
      QuicInternalException);
}

TEST(QuicServerMigrationNegotiatorClientTest, TestTransportParameterEncoding) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  supportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  supportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);

  auto expectedParameterId = TransportParameterId::server_migration_suite;
  uint64_t expectedParameterValue = 0x7; // 00..00111 in binary representation

  ASSERT_NO_THROW(
      QuicServerMigrationNegotiatorClient negotiator(supportedProtocols));
  QuicServerMigrationNegotiatorClient negotiator(supportedProtocols);

  ASSERT_NO_THROW(negotiator.onTransportParametersEncoding());
  auto encodedParameter = negotiator.onTransportParametersEncoding();

  auto cursor = folly::io::Cursor(encodedParameter.value.get());
  auto decodedValue = decodeQuicInteger(cursor).value().first;

  EXPECT_EQ(encodedParameter.parameter, expectedParameterId);
  EXPECT_EQ(decodedValue, expectedParameterValue);
}

TEST(QuicServerMigrationNegotiatorClientTest, TestReceptionOfWrongParameter) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  QuicServerMigrationNegotiatorClient negotiator(supportedProtocols);
  CustomIntegralTransportParameter wrongParameter(
      static_cast<uint64_t>(TransportParameterId::disable_migration), 0xFF);

  EXPECT_THROW(
      negotiator.onMigrationSuiteReceived(wrongParameter.encode()),
      QuicTransportException);
  EXPECT_TRUE(!negotiator.getNegotiatedProtocols());
}

TEST(QuicServerMigrationNegotiatorClientTest, TestReceptionOfWronglyEncodedParameter) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  QuicServerMigrationNegotiatorClient negotiator(supportedProtocols);
  CustomStringTransportParameter wronglyEncodedParameter(
      static_cast<uint64_t>(TransportParameterId::server_migration_suite), "");

  // Check that the raw data in wronglyEncodedParameter
  // is not accidentally a Quic integer.
  auto wronglyEncodedRaw = wronglyEncodedParameter.encode();
  auto cursor = folly::io::Cursor(wronglyEncodedRaw.value.get());
  auto quicInteger = decodeQuicInteger(cursor);
  ASSERT_TRUE(!quicInteger);

  EXPECT_THROW(
      negotiator.onMigrationSuiteReceived(wronglyEncodedParameter.encode()),
      QuicTransportException);
  EXPECT_TRUE(!negotiator.getNegotiatedProtocols());
}

TEST(QuicServerMigrationNegotiatorClientTest, TestReceptionOfParameterWithUnsupportedProtocol) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  QuicServerMigrationNegotiatorClient negotiator(supportedProtocols);
  CustomIntegralTransportParameter unsupportedProtocolParameter(
      static_cast<uint64_t>(TransportParameterId::server_migration_suite),
      static_cast<uint64_t>(ServerMigrationProtocol::POOL_OF_ADDRESSES));

  EXPECT_THROW(
      negotiator.onMigrationSuiteReceived(
          unsupportedProtocolParameter.encode()),
      QuicTransportException);
  EXPECT_TRUE(!negotiator.getNegotiatedProtocols());
}

TEST(QuicServerMigrationNegotiatorClientTest, TestReceptionOfParameterWithUnknownProtocol) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  QuicServerMigrationNegotiatorClient negotiator(supportedProtocols);

  // Test if the method recognizes the presence of an unknown protocol,
  // namely of a 1 in a bit position greater than the one identified by MAX.
  // This test is performed only if less than 64 different server migration
  // protocols have been defined, otherwise it has no meaning (there should
  // be no unknown protocols, if the encoding rules are respected).
  if (static_cast<uint64_t>(ServerMigrationProtocol::MAX) <
      (static_cast<uint64_t>(0x1) << 63)) {
    CustomIntegralTransportParameter unknownProtocolParameter(
        static_cast<uint64_t>(TransportParameterId::server_migration_suite),
        (static_cast<uint64_t>(0x1) << 63));
    EXPECT_THROW(
        negotiator.onMigrationSuiteReceived(unknownProtocolParameter.encode()),
        QuicTransportException);
    EXPECT_TRUE(!negotiator.getNegotiatedProtocols());
  }
}

TEST(QuicServerMigrationNegotiatorClientTest, TestSuccessfulNegotiationWithSingleProtocol) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  supportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  supportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  QuicServerMigrationNegotiatorClient negotiator(supportedProtocols);

  std::unordered_set<ServerMigrationProtocol> peerProtocols;
  peerProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  QuicServerMigrationNegotiatorClient fakePeerNegotiator(peerProtocols);
  auto peerParameter = fakePeerNegotiator.onTransportParametersEncoding();

  EXPECT_NO_THROW(negotiator.onMigrationSuiteReceived(peerParameter));
  auto negotiatedProtocols = negotiator.getNegotiatedProtocols();
  ASSERT_TRUE(negotiatedProtocols.hasValue());
  EXPECT_EQ(negotiatedProtocols->size(), 1);
  EXPECT_TRUE(negotiatedProtocols->count(ServerMigrationProtocol::SYMMETRIC));
}

TEST(QuicServerMigrationNegotiatorClientTest, TestSuccessfulNegotiationWithMultipleProtocols) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::EXPLICIT);
  supportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  supportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  QuicServerMigrationNegotiatorClient negotiator(supportedProtocols);

  std::unordered_set<ServerMigrationProtocol> peerProtocols;
  peerProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  peerProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  QuicServerMigrationNegotiatorClient fakePeerNegotiator(peerProtocols);
  auto peerParameter = fakePeerNegotiator.onTransportParametersEncoding();

  EXPECT_NO_THROW(negotiator.onMigrationSuiteReceived(peerParameter));
  auto negotiatedProtocols = negotiator.getNegotiatedProtocols();
  ASSERT_TRUE(negotiatedProtocols.hasValue());
  EXPECT_EQ(negotiatedProtocols->size(), 2);
  EXPECT_TRUE(
      negotiatedProtocols->count(ServerMigrationProtocol::POOL_OF_ADDRESSES));
  EXPECT_TRUE(negotiatedProtocols->count(ServerMigrationProtocol::SYMMETRIC));
}

TEST(QuicServerMigrationNegotiatorClientTest, TestUnsuccessfulNegotiation) {
  std::unordered_set<ServerMigrationProtocol> supportedProtocols;
  supportedProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
  supportedProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
  QuicServerMigrationNegotiatorClient negotiator(supportedProtocols);

  // If server_migration_suite has no 1s in its binary representation,
  // there are no protocols in common between the endpoints.
  CustomIntegralTransportParameter peerParameter(
      static_cast<uint64_t>(TransportParameterId::server_migration_suite), 0);

  EXPECT_NO_THROW(negotiator.onMigrationSuiteReceived(peerParameter.encode()));
  auto negotiatedProtocols = negotiator.getNegotiatedProtocols();
  ASSERT_TRUE(negotiatedProtocols.hasValue());
  EXPECT_TRUE(negotiatedProtocols->empty());
}

} // namespace test
} // namespace quic
