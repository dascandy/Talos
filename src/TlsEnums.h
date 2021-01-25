#pragma once

namespace Talos {

namespace Tls {

enum class Extension {
  server_name = 0,
  max_fragment_length = 1,
  status_request = 5,
  supported_groups = 10,
  signature_algorithms = 13,
  use_srtp = 14,
  heartbeat = 15,
  application_layer_protocol_negotiation = 16,
  signed_certificate_timestamp = 18,
  client_certificate_type = 19,
  server_certificate_type = 20,
  padding = 21,
  pre_shared_key = 41,
  early_data = 42,
  supported_versions = 43,
  cookie = 44,
  psk_key_exchange_modes = 45,
  certificate_authorities = 47,
  oid_filters = 48,
  post_handshake_auth = 49,
  signature_algorithms_cert = 50,
  key_share = 51,
};

enum class Handshake {
  client_hello = 1,
  server_hello = 2,
  new_session_ticket = 4,
  end_of_early_data = 5,
  encrypted_extensions = 8,
  certificate = 11,
  certificate_request = 13,
  certificate_verify = 15,
  finished = 20,
  key_update = 24,
  message_hash = 254,
};

}

}

