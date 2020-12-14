#pragma once

#include "caligo/x25519.h"
#include <cstring>
#include "reader.h"
#include "writer.h"

class TlsClientState;

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

struct TlsClientStateHandle {
  TlsClientState* state;
  enum class AuthenticationState : uint8_t {
    New,
    WaitingForServerHello,
    WaitingForEncryptedExtensions,
    WaitingForCertificate,
    WaitingForCertificateVerify,
    WaitingForFinished,
    Operational,
    Disconnected,
  };

  TlsClientStateHandle(std::string hostname, uint64_t currentTime);
  ~TlsClientStateHandle();
  TlsClientStateHandle(TlsClientStateHandle&& rhs) {
    state = rhs.state;
    rhs.state = nullptr;
  }
  TlsClientStateHandle& operator=(TlsClientStateHandle&& rhs) {
    state = rhs.state;
    rhs.state = nullptr;
    return *this;
  }
  AuthenticationState getAuthenticationState();
  TlsError getError();
  std::vector<uint8_t> startupExchange(std::span<const uint8_t> data);
  std::vector<uint8_t> receive_decode(std::span<const uint8_t> data);
  std::vector<uint8_t> send_encode(std::span<const uint8_t> data);
};

