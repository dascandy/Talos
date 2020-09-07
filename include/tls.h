#pragma once

#include "x25519.h"
#include <cstring>
#include "reader.h"
#include "writer.h"
#include "tcp_socket.h"

struct tls {
public:
  inline static future<tls> create(tcp_socket remote, std::string hostname)
  {
    tls connection(std::move(remote));
    co_await connection.initialize(std::move(hostname));
    co_return std::move(connection);
  }
  future<size_t> recvmsg(std::span<uint8_t> s);
  future<Void> sendmsg(std::span<const uint8_t> msg);
private:
  tls(tcp_socket sock);
  future<Void> initialize(std::string hostname);
  struct Impl;
  Impl* impl;
};


