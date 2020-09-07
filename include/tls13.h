#pragma once

#include "sha2.h"
#include "aes.h"

#include "hkdf.h"
#include "gcm.h"

template <typename Cipher, typename Hash>
struct TLS13 {
  secret<Hash> secret;
  Hash handshake;
  Hash original;
  GCM<Cipher> s;
  GCM<Cipher> c;
  TLS13(const std::vector<uint8_t>& sharedSecret, std::vector<uint8_t> handshakeSoFar)
  : secret(HKDF_HandshakeSecret<Hash>(sharedSecret))
  , handshake(handshakeSoFar)
  , original(handshakeSoFar)
  , s(secret.template get_key_iv<Cipher>(handshake, false, true))
  , c(secret.template get_key_iv<Cipher>(handshake, true, true))
  {
  }
  std::vector<uint8_t> notifyServerFinished(std::span<const uint8_t> message, std::span<const uint8_t> serverFinished) {
    std::vector<uint8_t> check = HMAC<Hash>(handshake, secret.get_finished_key(original, false));
    if (check.size() != serverFinished.size() || memcmp(check.data(), serverFinished.data(), check.size()) != 0) {
      fprintf(stderr, "Invalid serverFinished\n");
      return {};
    }

    addHandshakeData(message);
    std::vector<uint8_t> clientFinished = HMAC<Hash>(handshake, secret.get_finished_key(original, true));

    secret = HKDF_MasterSecret<Hash>(secret);
    s = secret.template get_key_iv<Cipher>(handshake, false);
    c = secret.template get_key_iv<Cipher>(handshake, true);

    return clientFinished;
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


