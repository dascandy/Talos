#pragma once

#include "caligo/aes.h"

#include "caligo/hkdf.h"
#include <cstdio>

inline void log_key(const char* name, std::span<const uint8_t> key) {
  static FILE* sslkeylog = fopen("/home/pebi/sslkeylog.txt", "wb");
  fprintf(sslkeylog, "%s 0000000000000000000000000000000000000000000000000000000000000000 ", name);
  for (auto c : key) {
    fprintf(sslkeylog, "%02x", c);
  }
  fprintf(sslkeylog, "\n");
  fprintf(sslkeylog, "\n");
  fflush(sslkeylog);
}

template <template <typename> typename AEAD, typename Cipher, typename Hash>
struct TLS13 {
  secret<Hash> secret;
  Hash handshake;
  Hash original;
  AEAD<Cipher> s;
  AEAD<Cipher> c;
  TLS13(const std::vector<uint8_t>& sharedSecret, std::vector<uint8_t> handshakeSoFar)
  : secret(HKDF_HandshakeSecret<Hash>(sharedSecret))
  , handshake(handshakeSoFar)
  , original(handshakeSoFar)
  , s(secret.template get_key_iv<Cipher>(original, false, true))
  , c(secret.template get_key_iv<Cipher>(original, true, true))
  {
    log_key("CLIENT_HANDSHAKE_TRAFFIC_SECRET", secret.get_traffic_secret(original, true, true));
    log_key("SERVER_HANDSHAKE_TRAFFIC_SECRET", secret.get_traffic_secret(original, false, true));
  }
  std::vector<uint8_t> notifyServerFinished(std::span<const uint8_t> message, std::span<const uint8_t> serverFinished) {
    std::vector<uint8_t> check = HMAC<Hash>(handshake, secret.get_finished_key(original, false));
    if (check.size() != serverFinished.size() || memcmp(check.data(), serverFinished.data(), check.size()) != 0) {
      fprintf(stderr, "Invalid serverFinished\n");
      return {};
    }

    addHandshakeData(message);
    return HMAC<Hash>(handshake, secret.get_finished_key(original, true));
  }
  std::vector<uint8_t> getHandshakeHash() {
    return handshake;
  }
  void switchToApplicationSecret() {
    secret = HKDF_MasterSecret<Hash>(secret);
    s = secret.template get_key_iv<Cipher>(handshake, false);
    c = secret.template get_key_iv<Cipher>(handshake, true);

    log_key("CLIENT_TRAFFIC_SECRET_0", secret.get_traffic_secret(handshake, true, false));
    log_key("SERVER_TRAFFIC_SECRET_0", secret.get_traffic_secret(handshake, false, false));
  }
  void updateTrafficSecrets() {
    secret = HKDF_UpdateSecret(secret);
    s = secret.template get_key_iv<Cipher>(handshake, false);
    c = secret.template get_key_iv<Cipher>(handshake, true);
  }
  void addHandshakeData(std::span<const uint8_t> data) {
    handshake.add(data);
  }
  std::pair<std::vector<uint8_t>, bool> Decrypt(const std::span<const uint8_t> ciphertext, const std::span<const uint8_t> aad, std::array<uint8_t, 16> tag) {
    return s.Decrypt(ciphertext, aad, tag);
  }
  std::pair<std::vector<uint8_t>, std::array<uint8_t, 16>> Encrypt(const std::span<const uint8_t> plaintext, const std::span<const uint8_t> aad) {
    return c.Encrypt(plaintext, aad);
  }
};


