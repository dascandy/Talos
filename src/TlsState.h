#pragma once

#include <talos/tls.h>
#include "X509Certificate.h"
#include "TlsMessages.h"
#include "Truststore.h"
#include "TlsEnums.h"

#include <variant>
#include <cstdio>
#include <set>
#include <sys/mman.h>

#include <caligo/random.h>
#include <caligo/sha2.h>
#include <caligo/hkdf.h>
#include <caligo/aes.h>
#include <caligo/ghash.h>
#include <caligo/gcm.h>
#include <caligo/x25519.h>

#include <writer.h>
#include <reader.h>

namespace Talos {

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
  std::vector<uint8_t> handshake_hmac(bool client) {
    return HMAC<Hash>(handshake, secret.get_finished_key(original, client));
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


struct NullCipher {
  std::vector<uint8_t> handshakeSoFar;
  void addHandshakeData(std::span<const uint8_t> data) {
    handshakeSoFar.insert(handshakeSoFar.end(), data.begin(), data.end());
  }
  std::vector<uint8_t> getHandshakeHash() {
    return {};
  }
  std::vector<uint8_t> handshake_hmac(bool) {
    return {};
  }
  void switchToApplicationSecret() {}
  void updateTrafficSecrets() {}
  std::pair<std::vector<uint8_t>, bool> Decrypt(const std::span<const uint8_t> , const std::span<const uint8_t> , std::array<uint8_t, 16> ) {
    return { {}, false };
  }
  std::pair<std::vector<uint8_t>, std::array<uint8_t, 16>> Encrypt(const std::span<const uint8_t> , const std::span<const uint8_t> ) {
    return { {}, {} };
  }
};

struct TlsState {
  ec_value privkey = ec_value::random_private_key();
  std::variant<NullCipher, TLS13<GCM, AES<128>, SHA2<256>>, TLS13<GCM, AES<256>, SHA2<384>>> cipher;
  x509certificate cert;
  x509certificate mycert;
  RsaPrivateKey* privatekey;
  std::string hostname;
  uint64_t currentTime;
  std::vector<uint8_t> recvbuffer;
  TlsStateHandle::AuthenticationState state = TlsStateHandle::AuthenticationState::ClientNew;
  TlsError error;

  TlsState(uint64_t currentTime)
  : currentTime(currentTime)
  , state(TlsStateHandle::AuthenticationState::ServerNew)
  {
  }

  TlsState(std::string hostname, uint64_t currentTime)
  : hostname(hostname)
  , currentTime(currentTime)
  , state(TlsStateHandle::AuthenticationState::ClientNew)
  {
  }

  TlsStateHandle::AuthenticationState getAuthenticationState() {
    return state;
  }

  TlsError getError() {
    return error;
  }

  std::vector<uint8_t> handleClientHello(std::span<const uint8_t> message, ec_value& privkey) {
    std::visit([message = std::span<const uint8_t>(message)](auto& c){ c.addHandshakeData(message); }, cipher);
    reader r(message);
    uint8_t handshakeType = r.read8();
    uint32_t size = r.read24be();
    if ((Tls::Handshake)handshakeType != Tls::Handshake::client_hello || size != message.size() - 4) {
      state = TlsStateHandle::AuthenticationState::Disconnected; 
      return {};
    }

    // Stuff we get from client hello
    std::set<uint16_t> cipherSuites;
    std::set<uint16_t> supportedGroups = { 0x17 };
    std::set<uint16_t> signatureAlgorithms = { };
    std::map<uint8_t, std::span<const uint8_t>> keyshares;
    uint16_t tlsver = r.read16be();
    if (tlsver != 0x0303) {
      state = TlsStateHandle::AuthenticationState::Disconnected; 
      return {};
    }

    r.get(32); // 'random' data, ignore

    uint8_t sessSize = r.read8();
    r.get(sessSize); // ignore session ID; just some more TLS1.2 make pretend
  
    uint16_t cipherSuiteSize = r.read16be();
    for (size_t n = 0; n < cipherSuiteSize / 2; n++) {
      cipherSuites.insert(r.read16be());
    }

    uint8_t compressions = r.read8();
    uint8_t compressionType = r.read8();
    if (compressions != 1 || compressionType != 0) {
      state = TlsStateHandle::AuthenticationState::Disconnected; 
      return {};
    }
    uint16_t extLength = r.read16be();
    reader exts = r.get(extLength);
    if (r.fail()) {
      state = TlsStateHandle::AuthenticationState::Disconnected; 
      return {};
    }
    while (exts.sizeleft()) {
      uint16_t key = exts.read16be();
      uint16_t size = exts.read16be();
      reader vals = exts.get(size);
      if (exts.fail()) {
        state = TlsStateHandle::AuthenticationState::Disconnected; 
        return {};
      }
      switch((Tls::Extension)key) {
      case Tls::Extension::key_share: // key share
      {
        while (vals.sizeleft()) {
          uint16_t keytype = vals.read16be();
          uint16_t keysize = vals.read16be();
          keyshares[keytype] = vals.get(keysize);
        }
      }
        break;
      case Tls::Extension::signature_algorithms:
      {
        signatureAlgorithms.clear();
        uint16_t count = vals.read16be();
        for (int n = 0; n < count; n += 2) {
          signatureAlgorithms.insert(vals.read16be());
        }
      }
        break;
      case Tls::Extension::psk_key_exchange_modes:
        break;
      case Tls::Extension::server_name:
      {
        vals.read16be();
        vals.read8();
        size_t stringLength = vals.read16be();
        auto sp = vals.get(stringLength);
        hostname = std::string((const char*)sp.data(), stringLength);
      }
        break;
      case Tls::Extension::supported_groups:
      {
        supportedGroups.clear();
        uint16_t count = vals.read16be();
        for (int n = 0; n < count; n += 2) {
          supportedGroups.insert(vals.read16be());
        }
      }
        break;
      case Tls::Extension::supported_versions: // tls version
        tlsver = vals.read16be();
        break;
      default: 
        fprintf(stderr, "Found %02X\n", key);
        break;
      }
    }
    
    if (tlsver != 0x0304) {
      state = TlsStateHandle::AuthenticationState::Disconnected; 
      return {};
    }
    if (!supportedGroups.contains(0x1D)) {
      state = TlsStateHandle::AuthenticationState::Disconnected; 
      return {};
    }
    // Need to check the actual algorithm our certificate(s) use
    /*
    if (!signatureAlgorithms.contains()) {
      state = TlsStateHandle::AuthenticationState::Disconnected; 
      return;
    }
    */

    auto& keyshare_x25519 = keyshares[0x1D];
    if (keyshare_x25519.size() != 0x20) {
      state = TlsStateHandle::AuthenticationState::Disconnected; 
      return {};
    }
    ec_value sharedkey = X25519(privkey, ec_value(keyshare_x25519));
    privkey.wipe();
    if (sharedkey == ec_value{0}) {
      state = TlsStateHandle::AuthenticationState::Disconnected; 
      return {};
    }
    std::vector<uint8_t> sharedData = sharedkey.as_bytes();
    sharedkey.wipe();
    if (sharedData.empty()) {
      state = TlsStateHandle::AuthenticationState::Disconnected; 
      return {};
    }
    uint16_t cipherSuite = 0;
    if (cipherSuites.contains(0x1302)) {
      cipherSuite = 0x1302;
    } else if (cipherSuites.contains(0x1301)) {
      cipherSuite = 0x1301;
    } else {
      state = TlsStateHandle::AuthenticationState::Disconnected; 
      return {};
    }
    state = TlsStateHandle::AuthenticationState::WaitingForClientFinished;

    // Now prepare the care package for the client
    // 1. ServerHello
    std::vector<uint8_t> rv = serverHello(cipherSuite, 0x1D, X25519(privkey, bignum<256>(9)).as_bytes());
    std::visit([message = std::span<const uint8_t>(message)](auto& c){ c.addHandshakeData(message); }, cipher);

    // Include the serverhello into the handshake hash so far
    if (cipherSuite == 0x1302) {
      cipher = TLS13<GCM, AES<256>, SHA2<384>>(sharedData, std::move(std::get<NullCipher>(cipher).handshakeSoFar));
    } else if (cipherSuite == 0x1301) {
      cipher = TLS13<GCM, AES<128>, SHA2<256>>(sharedData, std::move(std::get<NullCipher>(cipher).handshakeSoFar));
    }
    // In one encrypted block:
    // 2. EncryptedExtensions
    std::vector<uint8_t> encexts = EncryptedExtensions();
    // 3. Certificate
    std::vector<uint8_t> cert = Certificate({&mycert});
    std::vector<uint8_t> hashWithCert = std::visit([&](auto& c){ 
      c.addHandshakeData(encexts); 
      c.addHandshakeData(cert); 
      return c.getHandshakeHash();
    }, cipher);

    // 4. CertificateVerify
    std::vector<uint8_t> certverify = CertificateVerify(*privatekey, hashWithCert);

    std::vector<uint8_t> hashForFinished = std::visit([&](auto& c){ 
      c.addHandshakeData(certverify); 
      return c.getHandshakeHash();
    }, cipher);

    // 5. Finished
    std::vector<uint8_t> finished = Finished(hashForFinished);

    encexts.insert(encexts.end(), cert.begin(), cert.end());
    encexts.insert(encexts.end(), certverify.begin(), certverify.end());
    encexts.insert(encexts.end(), finished.begin(), finished.end());

    std::vector<uint8_t> encrypted = encrypt_message(encexts, 0x16);
    rv.insert(rv.end(), encrypted.begin(), encrypted.end());
    std::visit([&](auto& c){ 
      c.addHandshakeData(finished); 
    }, cipher);
    // Switch to application keys
    std::visit([&](auto& c) { c.switchToApplicationSecret(); }, cipher);

    state = TlsStateHandle::AuthenticationState::WaitingForClientFinished; 
    return rv;
  }

  void handleServerHello(std::span<const uint8_t> message, ec_value& privkey) {
    reader r(message);
    uint8_t handshakeType = r.read8();
    uint32_t size = r.read24be();
    if ((Tls::Handshake)handshakeType != Tls::Handshake::server_hello || size != message.size() - 4) {
      state = TlsStateHandle::AuthenticationState::Disconnected; 
      return;
    }

    uint16_t tlsver = r.read16be();
    if (tlsver != 0x0303) {
      state = TlsStateHandle::AuthenticationState::Disconnected; 
      return;
    }

    std::span<const uint8_t> serverRandom = r.get(32);
    static const std::array<const uint8_t, 32> helloRetryRequest = {
      0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 
      0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C, 
    };
    if (memcmp(helloRetryRequest.data(), serverRandom.data(), 32) == 0) {
      // Handle Hello Retry
      std::terminate();
    }

    uint8_t sessSize = r.read8();
    r.get(sessSize); // ignore session ID; just some more TLS1.2 make pretend

    uint16_t cipherSuite = r.read16be();
    r.read8(); // no compression.
    uint16_t extLength = r.read16be();
    reader exts = r.get(extLength);
    if (r.fail()) {
      state = TlsStateHandle::AuthenticationState::Disconnected; 
      return;
    }
    while (exts.sizeleft()) {
      uint16_t key = exts.read16be();
      uint16_t size = exts.read16be();
      reader vals = exts.get(size);
      if (exts.fail()) {
        state = TlsStateHandle::AuthenticationState::Disconnected; 
        return;
      }
      switch(key) {
      case 0x33: // key share
      {
        // yay, we get the server's key too
        uint16_t keytype = vals.read16be();
        uint16_t keysize = vals.read16be();
        if (keytype != 0x1D) {
          state = TlsStateHandle::AuthenticationState::Disconnected; 
          return;
        }
        if (keysize != 0x20) {
          state = TlsStateHandle::AuthenticationState::Disconnected; 
          return;
        }
        ec_value serverpub = ec_value(vals.get(0x20));
        if (vals.fail()) {
          state = TlsStateHandle::AuthenticationState::Disconnected; 
          return;
        }
        ec_value sharedkey = X25519(privkey, serverpub);
        privkey.wipe();
        std::vector<uint8_t> sharedData = sharedkey.as_bytes();
        if (sharedkey == ec_value{0}) {
          state = TlsStateHandle::AuthenticationState::Disconnected; 
          return;
        }
        sharedkey.wipe();
        switch(cipherSuite) {
        case 0x1301: 
          cipher = TLS13<GCM, AES<128>, SHA2<256>>(sharedData, std::move(std::get<NullCipher>(cipher).handshakeSoFar));
          break;
        case 0x1302: 
          cipher = TLS13<GCM, AES<256>, SHA2<384>>(sharedData, std::move(std::get<NullCipher>(cipher).handshakeSoFar));
          break;
        default: 
          state = TlsStateHandle::AuthenticationState::Disconnected; 
          return;
        }
      }
        break;
      case 0x2b: // tls version
        tlsver = vals.read16be();
        break;
      default: 
        fprintf(stderr, "Found %02X\n", key);
        break;
      }
    }
    if (tlsver == 0x0304) 
      state = TlsStateHandle::AuthenticationState::WaitingForEncryptedExtensions;
    else
      state = TlsStateHandle::AuthenticationState::Disconnected; 
  }

  void handleEncryptedExtensions(std::span<const uint8_t> message) {
    (void)message;
    state = TlsStateHandle::AuthenticationState::WaitingForServerCertificate;
    // check for illegal ones or weird ones
  }

  void handleCertificate(std::span<const uint8_t> message) {
    std::vector<x509certificate> certs;
    reader r(message);
    [[maybe_unused]] uint8_t context = r.read8();
    [[maybe_unused]] uint32_t certificateListLength = r.read24be();
    while (r.sizeleft()) {
      uint32_t certlength = r.read24be();
      std::span<const uint8_t> certdata = r.get(certlength);
      certs.push_back(parseCertificate(certdata, CertificateFormat::Der));
      uint16_t extLength = r.read16be();
      r.get(extLength);
    }

    bool isTrustable = Truststore::Instance().trust(certs, currentTime);
    if (isTrustable and certs[0].appliesTo(hostname)) {
      cert = std::move(certs[0]);
      state = TlsStateHandle::AuthenticationState::WaitingForServerCertificateVerify;
    } else {
      state = TlsStateHandle::AuthenticationState::Disconnected;
    }
  }

  void handleCertificateVerify(std::span<const uint8_t> message) {
    if (state != TlsStateHandle::AuthenticationState::WaitingForServerCertificateVerify) {
      state = TlsStateHandle::AuthenticationState::Disconnected;
      return;
    }

    // Check if it's signed correctly
    bool isValid = false;

    auto hash = std::visit([&](auto& c) -> std::vector<uint8_t>{ return c.getHandshakeHash(); }, cipher);
    std::vector<uint8_t> tosign;
    std::string tls13_prefix = "                                                                TLS 1.3, server CertificateVerify";
    tls13_prefix.push_back(0); // Do not move to the string literal above; there is *no* char[] constructor in std::string.
    tosign.insert(tosign.end(), tls13_prefix.begin(), tls13_prefix.end());
    tosign.insert(tosign.end(), hash.begin(), hash.end());

    uint16_t sigAlgo = (message[0] << 8) + message[1];
    std::span<const uint8_t> sig = message.subspan(4); // also skip over the size argument
    switch(sigAlgo) {
      case 0x0401:
        isValid = cert.pubkey->validateSignature(tosign, sig);
        break;
      case 0x0804:
      case 0x0809:
        isValid = cert.pubkey->validateRsaSsaPss(tosign, sig);
        break;
      default:
        break;
    }

    if (isValid) {
      state = TlsStateHandle::AuthenticationState::WaitingForServerFinished;
    } else {
      state = TlsStateHandle::AuthenticationState::Disconnected;
    }
  }

  std::vector<uint8_t> handleFinished(std::span<const uint8_t> message, std::span<const uint8_t> serverDigest) {
    if (state != TlsStateHandle::AuthenticationState::WaitingForServerFinished) {
      state = TlsStateHandle::AuthenticationState::Disconnected;
      return {};
    }

    std::vector<uint8_t> check = std::visit([&](auto& c) { return c.handshake_hmac(false); }, cipher);
    if (check.size() != serverDigest.size() || memcmp(check.data(), serverDigest.data(), check.size()) != 0) {
      state = TlsStateHandle::AuthenticationState::Disconnected;
      return {};
    }

    std::vector<uint8_t> hmac = std::visit([&](auto& c) -> std::vector<uint8_t> { 
      c.addHandshakeData(message); 
      return c.handshake_hmac(true);
    }, cipher);

    std::vector<uint8_t> clientFinished;
    clientFinished.push_back((uint8_t)Tls::Handshake::finished);
    clientFinished.push_back(0);
    clientFinished.push_back(0);
    clientFinished.push_back(hmac.size());
    clientFinished.insert(clientFinished.end(), hmac.begin(), hmac.end());

    std::vector<uint8_t> rv = encrypt_message(clientFinished, 0x16);
    std::visit([&](auto& c) { c.switchToApplicationSecret(); }, cipher);
    state = TlsStateHandle::AuthenticationState::ClientOperational;
    return rv;
  }

  std::vector<uint8_t> handleStartupMessage(uint16_t messageType, std::span<const uint8_t> message) {
    switch(state) {
      case TlsStateHandle::AuthenticationState::ServerNew:

      case TlsStateHandle::AuthenticationState::WaitingForClientFinished:

      case TlsStateHandle::AuthenticationState::ServerOperational:

      case TlsStateHandle::AuthenticationState::ClientOperational:
      case TlsStateHandle::AuthenticationState::Disconnected:
        std::terminate();


      case TlsStateHandle::AuthenticationState::ClientNew:
      {
        std::vector<uint8_t> hello = clientHello(hostname, X25519(privkey, bignum<256>(9)));
        std::visit([&](auto& c){ std::span hs = hello; c.addHandshakeData(hs.subspan(5)); }, cipher);
        state = TlsStateHandle::AuthenticationState::WaitingForServerHello;
        return hello;
      }
      case TlsStateHandle::AuthenticationState::WaitingForServerHello:
      {
        std::visit([message = std::span<const uint8_t>(message)](auto& c){ c.addHandshakeData(message); }, cipher);
        if (messageType == 0x16) {
          handleServerHello(message, privkey);
        } else {
          state = TlsStateHandle::AuthenticationState::Disconnected;
        }
        return {};
      }
      case TlsStateHandle::AuthenticationState::WaitingForEncryptedExtensions:
      {
        if (messageType != 0x1716) {
          state = TlsStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        std::visit([message = std::span<const uint8_t>(message)](auto& c){ c.addHandshakeData(message); }, cipher);
        reader r(message);
        uint8_t handshakeType = r.read8();
        if ((Tls::Handshake)handshakeType != Tls::Handshake::encrypted_extensions) {
          state = TlsStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        uint32_t size = r.read24be();
        std::span<const uint8_t> m = r.get(size);
        if (r.fail()) {
          state = TlsStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        handleEncryptedExtensions(m);
        return {};
      }
      break;

      case TlsStateHandle::AuthenticationState::WaitingForServerCertificate:
      {
        if (messageType != 0x1716) {
          state = TlsStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        std::visit([message = std::span<const uint8_t>(message)](auto& c){ c.addHandshakeData(message); }, cipher);
        reader r(message);
        uint8_t handshakeType = r.read8();
        switch((Tls::Handshake)handshakeType) {
          case Tls::Handshake::certificate_request:
            // TODO: implement certificate request handling for client
            state = TlsStateHandle::AuthenticationState::Disconnected;
            return {};
          case Tls::Handshake::certificate:
          {
            uint32_t size = r.read24be();
            std::span<const uint8_t> m = r.get(size);
            if (r.fail()) {
              state = TlsStateHandle::AuthenticationState::Disconnected;
              return {};
            }
            handleCertificate(m);
            return {};
          }
          default:
            state = TlsStateHandle::AuthenticationState::Disconnected;
            return {};
        }
      }
        break;

      case TlsStateHandle::AuthenticationState::WaitingForServerCertificateVerify:
      {
        if (messageType != 0x1716) {
          state = TlsStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        reader r(message);
        uint8_t handshakeType = r.read8();
        if ((Tls::Handshake)handshakeType != Tls::Handshake::certificate_verify) {
          state = TlsStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        uint32_t size = r.read24be();
        std::span<const uint8_t> m = r.get(size);
        if (r.fail()) {
          state = TlsStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        handleCertificateVerify(m);
        std::visit([message = std::span<const uint8_t>(message)](auto& c){ c.addHandshakeData(message); }, cipher);
      }
        return {};

      case TlsStateHandle::AuthenticationState::WaitingForServerFinished:
      {
        if (messageType != 0x1716) {
          state = TlsStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        reader r(message);
        uint8_t handshakeType = r.read8();
        if ((Tls::Handshake)handshakeType != Tls::Handshake::finished) {
          state = TlsStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        uint32_t size = r.read24be();
        std::span<const uint8_t> m = r.get(size);
        if (r.fail()) {
          state = TlsStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        return handleFinished(message, m);
      }
    }
  }

  std::vector<uint8_t> startupExchange(std::span<const uint8_t> data) {
    if (state == TlsStateHandle::AuthenticationState::ClientOperational ||
        state == TlsStateHandle::AuthenticationState::Disconnected) {
      return {};
    }
    // All state changes are triggered by messages, except for the initial message.
    if (state == TlsStateHandle::AuthenticationState::ClientNew) {
      return handleStartupMessage(0, {});
    }
    std::vector<uint8_t> rv;
    recvbuffer.insert(recvbuffer.end(), data.begin(), data.end());
    while (true) {
      reader r(recvbuffer);
      if (r.sizeleft() <= 5) {
        break;
      }

      uint16_t messageType = r.read8();
      uint16_t tlsver = r.read16be();
      if (tlsver != 0x0303) {
        state = TlsStateHandle::AuthenticationState::Disconnected;
        return {};
      }
      uint16_t size = r.read16be();
      if (r.sizeleft() >= size) {
        auto data = r.get(size);
        std::vector<uint8_t> messageBuffer;
        if (messageType == 0x17) {
          auto [ddata, valid] = std::visit([&](auto& c){ 
            std::vector<uint8_t> aad;
            aad.resize(5);
            memcpy(aad.data(), recvbuffer.data(), 5);
            std::array<uint8_t, 16> tag;
            memcpy(tag.data(), data.data() + data.size() - 16, 16);
            return c.Decrypt(data.subspan(0, data.size() - 16), aad, tag);
          }, cipher);
          if (!valid) {
            state = TlsStateHandle::AuthenticationState::Disconnected;
            return {};
          }
          while (!ddata.empty() && ddata.back() == 0) ddata.pop_back();
          if (ddata.empty()) {
            state = TlsStateHandle::AuthenticationState::Disconnected;
            return {};
          }
          messageType = 0x1700 | ddata.back();
          ddata.pop_back();
          reader dr(ddata);
          while (dr.sizeleft() >= 4) {
            reader r2 = dr;
            r2.read8();
            uint32_t size = r2.read24be();
            std::span<const uint8_t> m = dr.get(size + 4);
            auto feedback = handleStartupMessage(messageType, m);
            rv.insert(rv.end(), feedback.begin(), feedback.end());
          }
        } else if (messageType == 0x14) {
          // Legacy TLS1.2 compat message; ignore
        } else if (messageType == 0x16) {
          messageBuffer = std::vector<uint8_t>(data.data(), data.data() + data.size());
          auto feedback = handleStartupMessage(messageType, messageBuffer);
          rv.insert(rv.end(), feedback.begin(), feedback.end());
        }
        memmove(recvbuffer.data(), recvbuffer.data() + 5 + size, recvbuffer.size() - size - 5);
        recvbuffer.resize(recvbuffer.size() - size - 5);
      }
    }
    return rv;
  }

  std::vector<uint8_t> encrypt_message(std::span<const uint8_t> msg, uint8_t msgType) {
    std::vector<uint8_t> message;
    message.reserve(msg.size() + 1);
    message.insert(message.end(), msg.begin(), msg.end());
    message.push_back(msgType);
    size_t sizeNoHeader = msg.size() + 17; // 16 for tag, 1 for msgtype
    std::vector<uint8_t> aad;
    aad.reserve(msg.size() + 22);
    aad.resize(5);
    aad[0] = 0x17;
    aad[1] = 0x03;
    aad[2] = 0x03;
    aad[3] = ((sizeNoHeader >> 8) & 0xFF);
    aad[4] = (sizeNoHeader & 0xFF);
    auto [emsg, tag] = std::visit([&message, &aad](auto& c){ return c.Encrypt(message, aad);}, cipher);
    message = std::move(aad);
    message.resize(5+sizeNoHeader);
    memcpy(message.data() + 5, emsg.data(), emsg.size());
    memcpy(message.data() + 5 + emsg.size(), tag.data(), tag.size());
    return message;
  }

  // postcondition: a next receive_decode without argument will return nothing
  std::vector<uint8_t> receive_decode(std::span<const uint8_t> data) {
    if (state != TlsStateHandle::AuthenticationState::ClientOperational) {
      return {};
    }

    std::vector<uint8_t> rv;
    recvbuffer.insert(recvbuffer.end(), data.begin(), data.end());
    while (true) {
      reader r(recvbuffer);
      if (r.sizeleft() < 5) {
        return rv;
      }
      uint16_t messageType = r.read8();
      uint16_t tlsver = r.read16be();
      if (tlsver != 0x0303) {
        state = TlsStateHandle::AuthenticationState::Disconnected;
        return rv;
      }
      uint16_t size = r.read16be();
      if (r.sizeleft() < size) {
        return rv;
      }
      auto data = r.get(size);
      std::vector<uint8_t> message;
      if (messageType == 0x17) {
        auto [ddata, valid] = std::visit([&](auto& c){
          std::vector<uint8_t> aad;
          aad.resize(5);
          memcpy(aad.data(), recvbuffer.data(), 5);
          std::array<uint8_t, 16> tag;
          memcpy(tag.data(), data.data() + data.size() - 16, 16);
          return c.Decrypt(data.subspan(0, data.size() - 16), aad, tag);
        }, cipher);
        if (!valid) {
          state = TlsStateHandle::AuthenticationState::Disconnected;
          return rv;
        }
        while (!ddata.empty() && ddata.back() == 0) ddata.pop_back();
        if (ddata.empty()) {
          state = TlsStateHandle::AuthenticationState::Disconnected;
          return rv;
        }
        messageType = 0x1700 | ddata.back();
        ddata.pop_back();
        message = std::move(ddata);
      } else {
        message = std::vector<uint8_t>(data.data(), data.data() + data.size());
      }

      memmove(recvbuffer.data(), recvbuffer.data() + 5 + size, recvbuffer.size() - size - 5);
      recvbuffer.resize(recvbuffer.size() - size - 5);

      switch(messageType) {
        case 0x1717:
          // Data message
          rv.insert(rv.end(), message.begin(), message.end());
          break;
        case 0x1716:
        {
          reader r(message);
          uint8_t handshakeType = r.read8();

          // Handshake message
          switch((Tls::Handshake)handshakeType) {
          case Tls::Handshake::new_session_ticket:
            break;
          case Tls::Handshake::certificate_request:
          case Tls::Handshake::key_update:
          default:
            // invalid message
            state = TlsStateHandle::AuthenticationState::Disconnected;
            break;
          }
        }
          break;
        case 0x1715:
          if (message.size() < 2) {
            state = TlsStateHandle::AuthenticationState::Disconnected;
            break;
          }

          // Alert
          error = (TlsError)message[1];
          state = TlsStateHandle::AuthenticationState::Disconnected;
          break;
        //   Any records following a Finished message MUST be encrypted under the
        //   appropriate application traffic key as described in Section 7.2.  In
        //   particular, this includes any alerts sent by the server in response
        //   to client Certificate and CertificateVerify messages.
        case 0x14:
        case 0x15:
        case 0x16:
        case 0x17:
        case 0x1714: // This message is invalid in TLS 1.3 per spec
          state = TlsStateHandle::AuthenticationState::Disconnected;
          break;
        default:
          state = TlsStateHandle::AuthenticationState::Disconnected;
          break;
      }
    }
  }

  std::vector<uint8_t> send_encode(std::span<const uint8_t> data) {
    if (state != TlsStateHandle::AuthenticationState::ClientOperational) return {};

    return encrypt_message(data, 0x17);
  }
};

static_assert(sizeof(TlsState) < 4096);

}


