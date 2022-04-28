#include "QuicIPAddress.h"

QuicIPAddress::QuicIPAddress(const folly::SocketAddress& address) {
  if (address.getIPAddress().isV4()) {
    ipv4Address = address.getIPAddress().asV4();
    ipv4Port = address.getPort();
  } else if (address.getIPAddress().isV6()) {
    ipv6Address = address.getIPAddress().asV6();
    ipv6Port = address.getPort();
  }
}

QuicIPAddress::QuicIPAddress(
    const folly::SocketAddress& addressV4,
    const folly::SocketAddress& addressV6) {
  CHECK(addressV4.getIPAddress().isV4() && addressV6.getIPAddress().isV6());
  ipv4Address = addressV4.getIPAddress().asV4();
  ipv4Port = addressV4.getPort();
  ipv6Address = addressV6.getIPAddress().asV6();
  ipv6Port = addressV6.getPort();
}

QuicIPAddress::QuicIPAddress(
    const folly::IPAddress& address,
    const uint16_t& port) {
  if (address.isV4()) {
    ipv4Address = address.asV4();
    ipv4Port = port;
  } else if (address.isV6()) {
    ipv6Address = address.asV6();
    ipv6Port = port;
  }
}

QuicIPAddress::QuicIPAddress(
    const folly::IPAddressV4& ipv4Address,
    const uint16_t& ipv4Port,
    const folly::IPAddressV6& ipv6Address,
    const uint16_t& ipv6Port)
    : ipv4Address(ipv4Address),
      ipv4Port(ipv4Port),
      ipv6Address(ipv6Address),
      ipv6Port(ipv6Port) {}

bool QuicIPAddress::isAllZero() const {
  return ipv4Address.isZero() && ipv4Port == 0 && ipv6Address.isZero() &&
      ipv6Port == 0;
}

bool QuicIPAddress::operator==(const QuicIPAddress& rhs) const {
  return ipv4Address == rhs.ipv4Address && ipv4Port == rhs.ipv4Port &&
      ipv6Address == rhs.ipv6Address && ipv6Port == rhs.ipv6Port;
}

bool QuicIPAddress::operator!=(const QuicIPAddress& rhs) const {
  return !(rhs == *this);
}

size_t QuicIPAddressHash::operator()(const QuicIPAddress& quicIpAddress) const {
  return folly::hash::hash_combine(
      quicIpAddress.ipv4Address.hash(),
      folly::hash::fnv32_buf(
          &quicIpAddress.ipv4Port, sizeof(quicIpAddress.ipv4Port)),
      quicIpAddress.ipv6Address.hash(),
      folly::hash::fnv32_buf(
          &quicIpAddress.ipv6Port, sizeof(quicIpAddress.ipv6Port)));
}
