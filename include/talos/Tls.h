#pragma once

#include <cstring>
#include <string>
#include <cstdint>
#include <vector>
#include <span>

namespace Talos {

struct TlsState;

enum class TlsError : uint16_t {
  close_notify = 0,
  unexpected_message = 10,
  bad_record_mac = 20,
  record_overflow = 22,
  handshake_failure = 40,
  bad_certificate = 42,
  unsupported_certificate = 43,
  certificate_revoked = 44,
  certificate_expired = 45,
  certificate_unknown = 46,
  illegal_parameter = 47,
  unknown_ca = 48,
  access_denied = 49,
  decode_error = 50,
  decrypt_error = 51,
  protocol_version = 70,
  insufficient_security = 71,
  internal_error = 80,
  inappropriate_fallback = 86,
  user_canceled = 90,
  missing_extension = 109,
  unsupported_extension = 110,
  unrecognized_name = 112,
  bad_certificate_status_response = 113,
  unknown_psk_identity = 115,
  certificate_required = 116,
  no_application_protocol = 120,
};

std::string to_string(TlsError error);

enum class AuthenticationState : uint8_t {
  ClientNew,
  WaitingForServerHello,
  WaitingForEncryptedExtensions,
  WaitingForServerCertificate,
  WaitingForServerCertificateVerify,
  WaitingForServerFinished,
  ClientOperational,
  ServerNew,
  WaitingForClientFinished,
  ServerOperational,
  Disconnected,
};

std::string to_string(AuthenticationState state);

struct TlsContext;
struct TlsContextHandle {
  TlsContextHandle();
  ~TlsContextHandle();
  void AddIdentity(std::string_view certificatesPem, std::string_view privateKeyPem);
  TlsContext* context;
};

struct TlsStateHandle {
public:
  static TlsStateHandle createServer(TlsContextHandle& handle, uint64_t currentTime);
  static TlsStateHandle createClient(std::string hostname, TlsContextHandle& handle, uint64_t currentTime);
  ~TlsStateHandle();
  TlsStateHandle(TlsStateHandle&& rhs) {
    state = rhs.state;
    rhs.state = nullptr;
  }
  TlsStateHandle& operator=(TlsStateHandle&& rhs) {
    state = rhs.state;
    rhs.state = nullptr;
    return *this;
  }

  AuthenticationState getAuthenticationState();
  TlsError getError();
  std::vector<uint8_t> startupExchange(std::span<const uint8_t> data);
  std::vector<uint8_t> receive_decode(std::span<const uint8_t> data);
  std::vector<uint8_t> send_encode(std::span<const uint8_t> data);
private:
  TlsStateHandle(TlsState* state)
  : state(state)
  {}
  TlsState* state;
};

}


