#include <quic/handshake/QuicKeyLogWriter.h>

namespace quic {

QuicKeyLogWriter::QuicKeyLogWriter(const Config& config) {
  config_ = config;

  switch (config.writeMode) {
    case WriteMode::APPEND:
      outputFile_.open(config_.fileName.c_str(), std::ios_base::app);
      break;
    case WriteMode::OVERWRITE:
      outputFile_.open(config_.fileName.c_str(), std::ios_base::trunc);
      break;
    default:
      throw std::runtime_error("WriteMode not implemented");
  }

  if (outputFile_.fail()) {
    throw std::runtime_error("Error opening NSS key log output file");
  }
}

void QuicKeyLogWriter::write(
    const fizz::Random& clientRandom,
    QuicKeyLogWriter::Label label,
    const folly::ByteRange& secret) {
  switch (config_.flushPolicy) {
    case FlushPolicy::DEFAULT:
      outputFile_ << generateLogLine(clientRandom, label, secret);
      break;
    case FlushPolicy::IMMEDIATELY:
      outputFile_ << generateLogLine(clientRandom, label, secret) << std::flush;
      break;
    default:
      throw std::runtime_error("FlushPolicy not implemented");
  }
}

std::string QuicKeyLogWriter::generateLogLine(
    const fizz::Random& clientRandom,
    QuicKeyLogWriter::Label label,
    const folly::ByteRange& secret) {
  return fmt::format(
      "{0} {1} {2}\n",
      labelToString(label),
      folly::hexlify(clientRandom),
      folly::hexlify(secret));
}

std::string QuicKeyLogWriter::labelToString(QuicKeyLogWriter::Label label) {
  switch (label) {
    case Label::RSA:
      return "RSA";
    case Label::CLIENT_RANDOM:
      return "CLIENT_RANDOM";
    case Label::CLIENT_EARLY_TRAFFIC_SECRET:
      return "CLIENT_EARLY_TRAFFIC_SECRET";
    case Label::CLIENT_HANDSHAKE_TRAFFIC_SECRET:
      return "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
    case Label::SERVER_HANDSHAKE_TRAFFIC_SECRET:
      return "SERVER_HANDSHAKE_TRAFFIC_SECRET";
    case Label::CLIENT_TRAFFIC_SECRET_0:
      return "CLIENT_TRAFFIC_SECRET_0";
    case Label::SERVER_TRAFFIC_SECRET_0:
      return "SERVER_TRAFFIC_SECRET_0";
    case Label::EARLY_EXPORTER_SECRET:
      return "EARLY_EXPORTER_SECRET";
    case Label::EXPORTER_SECRET:
      return "EXPORTER_SECRET";
    default:
      break;
  }
  return "";
}

} // namespace quic
