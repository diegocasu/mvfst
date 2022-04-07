add_library(
  mvfst_server_migration STATIC
  QuicServerMigrationNegotiator.cpp
  QuicServerMigrationNegotiatorClient.cpp
)

target_include_directories(
  mvfst_server_migration PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_server_migration
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_server_migration
  mvfst_constants
  mvfst_exception
  mvfst_handshake
)

target_link_libraries(
  mvfst_server_migration PUBLIC
  Folly::folly
  mvfst_constants
  mvfst_exception
  mvfst_handshake
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/loss/${header_dir})
endforeach()

install(
  TARGETS mvfst_server_migration
  EXPORT mvfst-exports
  DESTINATION lib
)

add_subdirectory(test)
