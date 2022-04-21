add_library(
  mvfst_server_migration_negotiator STATIC
  QuicServerMigrationNegotiator.cpp
  QuicServerMigrationNegotiatorClient.cpp
  QuicServerMigrationNegotiatorServer.cpp
)

target_include_directories(
  mvfst_server_migration_negotiator PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_server_migration_negotiator
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_server_migration_negotiator
  mvfst_constants
  mvfst_exception
  mvfst_handshake
)

target_link_libraries(
  mvfst_server_migration_negotiator PUBLIC
  Folly::folly
  mvfst_constants
  mvfst_exception
  mvfst_handshake
)

add_library(
  mvfst_server_migration_frame_functions
  ServerMigrationFrameFunctions.cpp
)

target_include_directories(
  mvfst_server_migration_frame_functions PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_server_migration_frame_functions
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_server_migration_frame_functions
  mvfst_server_state
  mvfst_codec_types
)

target_link_libraries(
  mvfst_server_migration_frame_functions PUBLIC
  Folly::folly
  mvfst_server_state
  mvfst_codec_types
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/servermigration/${header_dir})
endforeach()

install(
  TARGETS mvfst_server_migration_negotiator
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_server_migration_frame_functions
  EXPORT mvfst-exports
  DESTINATION lib
)

add_subdirectory(test)
