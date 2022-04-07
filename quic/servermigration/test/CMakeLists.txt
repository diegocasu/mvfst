if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET QuicServerMigrationNegotiatorClientTest
  SOURCES
  QuicServerMigrationNegotiatorClientTest.cpp
  DEPENDS
  Folly::folly
  mvfst_server_migration
  mvfst_constants
  mvfst_exception
  mvfst_handshake
)
