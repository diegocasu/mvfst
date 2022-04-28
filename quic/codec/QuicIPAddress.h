#pragma once

#include <folly/SocketAddress.h>
#include <glog/logging.h>

struct QuicIPAddress {
  folly::IPAddressV4 ipv4Address{"0.0.0.0"};
  uint16_t ipv4Port{0};
  folly::IPAddressV6 ipv6Address{"::"};
  uint16_t ipv6Port{0};

  /**
   * Creates an all-zero Quic IP address.
   */
  explicit QuicIPAddress() = default;

  /**
   * Creates a Quic IP address specifying a single address and port of a
   * chosen family, either IPv4 or IPv6; the other address and port are set
   * using an all-zero representation. The address family is automatically
   * inferred from the argument.
   * @param address  the socket address specifying an IP address and port.
   */
  explicit QuicIPAddress(const folly::SocketAddress& address);

  QuicIPAddress(
      const folly::SocketAddress& addressV4,
      const folly::SocketAddress& addressV6);

  /**
   * Creates a Quic IP address specifying a single address and port of a
   * chosen family, either IPv4 or IPv6; the other address and port are set
   * using an all-zero representation. The address family is automatically
   * inferred from the arguments.
   * @param address  the IP address of the chosen family.
   * @param port     the port.
   */
  QuicIPAddress(const folly::IPAddress& address, const uint16_t& port);

  QuicIPAddress(
      const folly::IPAddressV4& ipv4Address,
      const uint16_t& ipv4Port,
      const folly::IPAddressV6& ipv6Address,
      const uint16_t& ipv6Port);

  bool operator==(const QuicIPAddress& rhs) const;
  bool operator!=(const QuicIPAddress& rhs) const;
  bool isAllZero() const;
};

struct QuicIPAddressHash {
  size_t operator()(const QuicIPAddress& quicIpAddress) const;
};
