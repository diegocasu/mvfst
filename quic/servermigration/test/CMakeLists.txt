if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET QuicServerMigrationNegotiatorClientTest
  SOURCES
  QuicServerMigrationNegotiatorClientTest.cpp
  DEPENDS
  Folly::folly
  mvfst_server_migration_negotiator
  mvfst_constants
  mvfst_exception
  mvfst_handshake
)

quic_add_test(TARGET QuicServerMigrationNegotiatorServerTest
  SOURCES
  QuicServerMigrationNegotiatorServerTest.cpp
  DEPENDS
  Folly::folly
  mvfst_server_migration_negotiator
  mvfst_constants
  mvfst_exception
  mvfst_handshake
)

quic_add_test(TARGET QuicServerMigrationFrameFunctionsTest
  SOURCES
  ServerMigrationFrameFunctionsTest.cpp
  DEPENDS
  Folly::folly
  mvfst_server
  mvfst_constants
  mvfst_exception
  mvfst_server_migration_frame_functions
)

quic_add_test(TARGET QuicServerMigrationIntegrationTest
  SOURCES
  QuicServerMigrationIntegrationTest.cpp
  DEPENDS
  Folly::folly
  mvfst_server
  mvfst_client
  mvfst_server_migration_negotiator
  mvfst_constants
  mvfst_exception
  mvfst_test_utils
)
