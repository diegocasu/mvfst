
#pragma once

#include <fizz/protocol/Types.h>
#include <fmt/format.h>
#include <folly/Range.h>
#include <fstream>

namespace quic {

/**
 * Logger that dumps TLS secrets to file using the NSS format.
 * The code is based on fizz::KeyLogWriter (not extended due
 * to the stream variable being private) and enhanced to give
 * the possibility to configure:
 * 1) an immediate flush of the output stream after each write;
 * 2) the write mode (append or overwrite).
 */
class QuicKeyLogWriter {
 public:
  enum class Label {
    // 48 bytes for the premaster secret, encoded
    // as 96 hexadecimal characters.
    RSA,

    // 48 bytes for the master secret, encoded
    // as 96 hexadecimal characters
    // (for SSL 3.0, TLS 1.0, 1.1 and 1.2).
    CLIENT_RANDOM,

    // the hex-encoded early traffic secret
    // for the client side (for TLS 1.3).
    CLIENT_EARLY_TRAFFIC_SECRET,

    // the hex-encoded handshake traffic secret
    // for the client side (for TLS 1.3).
    CLIENT_HANDSHAKE_TRAFFIC_SECRET,

    // the hex-encoded handshake traffic secret
    // for the server side (for TLS 1.3).
    SERVER_HANDSHAKE_TRAFFIC_SECRET,

    // the first hex-encoded application traffic secret
    // for the client side (for TLS 1.3).
    CLIENT_TRAFFIC_SECRET_0,

    // the first hex-encoded application traffic secret
    // for the server side (for TLS 1.3).
    SERVER_TRAFFIC_SECRET_0,

    // the hex-encoded early exporter secret (for TLS 1.3,
    // used for 0-RTT keys in older QUIC drafts).
    EARLY_EXPORTER_SECRET,

    // the hex-encoded exporter secret (for TLS 1.3,
    // used for 1-RTT keys in older QUIC drafts).
    EXPORTER_SECRET
  };

  enum class FlushPolicy {
    // Default flush behaviour of ofstream.
    DEFAULT,

    // Flush the stream after each write operation.
    IMMEDIATELY
  };

  enum class WriteMode {
    APPEND,
    OVERWRITE
  };

  struct Config {
    std::string fileName;
    FlushPolicy flushPolicy = FlushPolicy::DEFAULT;
    WriteMode writeMode = WriteMode::APPEND;
  };

  /**
   * Instantiate a QuicKeyLogWriter.
   * @param config  configuration of the writer.
   */
  explicit QuicKeyLogWriter(const Config& config);

  /**
   * Append a new log line to the key log file.
   * @param clientRandom  32 bytes random value from the Client Hello
   *                      message used as identifier of each NSS key log line.
   * @param label         type of the log defined in
   *                      https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format.
   * @param secret        the secret corresponding to the secret type.
   */
  void write(
      const fizz::Random& clientRandom,
      QuicKeyLogWriter::Label label,
      const folly::ByteRange& secret);

  /**
   * Generate an NSS key log line.
   * @param clientRandom  32 bytes random value from the Client Hello
   *                      message used as identifier of each NSS key log line.
   * @param label         type of the log defined in
   *                      https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format.
   * @param secret        the secret corresponding to the secret type.
   * @return              the NSS key log line ended with a new line character.
   */
  static std::string generateLogLine(
      const fizz::Random& clientRandom,
      QuicKeyLogWriter::Label label,
      const folly::ByteRange& secret);

 private:
  /**
  * Convert the Label enumerate to string.
  */
  static std::string labelToString(QuicKeyLogWriter::Label label);

  std::ofstream outputFile_;
  Config config_;
};

} // namespace quic
