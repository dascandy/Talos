#include <variant>
#include "caligo/random.h"
#include "caligo/sha2.h"
#include "caligo/hkdf.h"
#include "caligo/aes.h"
#include "caligo/ghash.h"
#include "caligo/gcm.h"
#include "writer.h"
#include "caligo/x25519.h"
#include <reader.h>
#include "tls_messages.h"
#include <cstdio>
#include "tls13.h"
#include <talos/tls.h>
#include "x509_certificate.h"
#include "truststore.h"
#include <sys/mman.h>

std::string to_string(TlsError error) {
  (void)error;
  return "FAIL";
}

  enum class TrustClass {
    TrustLevel = 0x0F,
    UserTrusted = 1, // user vouched for this fqdn with this cert explicitly
    UserBlanketCaTrusted = 2, // user added a blanket CA that trusts this
    UserCaTrusted = 3, // user added a targeted CA that trusts this
    BlanketTrustchainValid = 6, // default trust chain contains a blanket CA for this
    TrustchainValid = 7, // default trust chain contains a targeted CA that trusts this

    Validity = 0xF0,
    NotYetValid = 0x10,
    CurrentlyValid = 0x20,
    WithinLeewayPeriod = 0x30,
    Expired = 0x40,

    DomainMatch = 0xF00,
    MainFqdnMatch = 0x100,
    SANFqdnMatch = 0x200,
    WildcardMatch = 0x300,
    NoMatch = 0x400,

    CaaRecordStatus = 0x3000,
    NoCaaRecord = 0x0000,
    CaaInvalid = 0x1000,
    CaaValid = 0x2000,

    SecurityLevel = 0xFF0000,
    NoSecurity = 0x00000, 
    Level1Security = 0x10000, // 1990 level security. Using hash prior to md5, export-level (40-bit) crypto, RSA512 or equiv
    Level2Security = 0x20000, // 1995 level security. Using md5, 56-bit DES or equiv, RSA768 or equiv
    Level3Security = 0x30000, // 2000 level security. Using SHA0, 3des or equiv, rsa1024 or equiv
    Level4Security = 0x40000, // 2005 level security. Using SHA1, aes-128 or equiv, rsa1536 or equiv. TLS1.0
    Level5Security = 0x50000, // 2010 level security. Using SHA2-256, aes-128 or equiv, rsa2048 or equiv. TLS1.1
    Level6Security = 0x60000, // 2015 level security. Using SHA2-512, AES-256 or equiv, rsa3072 or equiv. TLS1.2
    Level7Security = 0x70000, // 2020 level security. Using poly1305-chacha20, rsa4096, aes-512, x25519/p256 or equiv, with SHA3. TLS1.3
  };

struct NullCipher {
  std::vector<uint8_t> handshakeSoFar;
  void addHandshakeData(std::span<const uint8_t> data) {
    handshakeSoFar.insert(handshakeSoFar.end(), data.begin(), data.end());
  }
  std::vector<uint8_t> getHandshakeHash() {
    return {};
  }
  std::vector<uint8_t> notifyServerFinished(std::span<const uint8_t>, std::span<const uint8_t>) {
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

class TlsClientState {
public:
  ec_value privkey = ec_value::random_private_key();
  std::variant<NullCipher, TLS13<GCM, AES<128>, SHA2<256>>, TLS13<GCM, AES<256>, SHA2<384>>> cipher;
  x509certificate cert;
  std::string hostname;
  uint64_t currentTime;
  std::vector<uint8_t> recvbuffer;
  TlsClientStateHandle::AuthenticationState state = TlsClientStateHandle::AuthenticationState::New;
  TlsError error;

  TlsClientState(std::string hostname, uint64_t currentTime) 
  : hostname(hostname)
  , currentTime(currentTime)
  {
  }


  TlsClientStateHandle::AuthenticationState getAuthenticationState() {
    return state;
  }

  TlsError getError() {
    return error;
  }

  enum class ServerHelloState {
    Invalid,
    HelloRetry,
    Valid
  };

  ServerHelloState handleServerHello(std::span<const uint8_t> message, ec_value& privkey) {
    reader r(message);
    uint8_t handshakeType = r.read8();
    uint32_t size = r.read24be();
    if (handshakeType != 0x02 || size != message.size() - 4) return ServerHelloState::Invalid;

    uint16_t tlsver = r.read16be();
     if (tlsver != 0x0303) return ServerHelloState::Invalid;

    std::span<const uint8_t> serverRandom = r.get(32);
    static const std::array<const uint8_t, 32> helloRetryRequest = {
      0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 
      0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C, 
    };
    if (memcmp(helloRetryRequest.data(), serverRandom.data(), 32) == 0) return ServerHelloState::HelloRetry;

    uint8_t sessSize = r.read8();
    r.get(sessSize); // ignore session ID; just some more TLS1.2 make pretend

    uint16_t cipherSuite = r.read16be();
    r.read8(); // no compression.
    uint16_t extLength = r.read16be();
    reader exts = r.get(extLength);
    if (r.fail()) return ServerHelloState::Invalid;
    while (exts.sizeleft()) {
      uint16_t key = exts.read16be();
      uint16_t size = exts.read16be();
      reader vals = exts.get(size);
      if (exts.fail()) return ServerHelloState::Invalid;
      switch(key) {
      case 0x33: // key share
      {
        // yay, we get the server's key too
        uint16_t keytype = vals.read16be();
        uint16_t keysize = vals.read16be();
        if (keytype != 0x1D) return ServerHelloState::Invalid;
        if (keysize != 0x20) return ServerHelloState::Invalid;
        ec_value serverpub = ec_value(vals.get(0x20));
        if (vals.fail()) return ServerHelloState::Invalid;
        ec_value sharedkey = X25519(privkey, serverpub);
        privkey.wipe();
        std::vector<uint8_t> sharedData = sharedkey.as_bytes();
        if (sharedkey == ec_value{0}) return ServerHelloState::Invalid;
        sharedkey.wipe();
        switch(cipherSuite) {
        case 0x1301: 
          cipher = TLS13<GCM, AES<128>, SHA2<256>>(sharedData, std::move(std::get<NullCipher>(cipher).handshakeSoFar));
          break;
        case 0x1302: 
          cipher = TLS13<GCM, AES<256>, SHA2<384>>(sharedData, std::move(std::get<NullCipher>(cipher).handshakeSoFar));
          break;
        default: 
          return ServerHelloState::Invalid;
        }
      }
        break;
      case 0x2b: // tls version
        tlsver = vals.read16be();
        break;
      default: 
        fprintf(stderr, "Found %02X\n", key);
        break;
//          return ServerHelloState::Invalid;
      }
    }
    if (tlsver != 0x0304) return ServerHelloState::Invalid;
    return ServerHelloState::Valid;
  }

  void handleEncryptedExtensions(std::span<const uint8_t> message) {
    (void)message;
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
      state = TlsClientStateHandle::AuthenticationState::WaitingForCertificateVerify;
    } else {
      state = TlsClientStateHandle::AuthenticationState::Disconnected;
    }
  }

  void handleCertificateVerify(std::span<const uint8_t> message) {
    if (state != TlsClientStateHandle::AuthenticationState::WaitingForCertificateVerify) {
      state = TlsClientStateHandle::AuthenticationState::Disconnected;
      return;
    }

    // Check if it's signed correctly
    bool isValid = false;

    auto hash = std::visit([&](auto& c) -> std::vector<uint8_t>{ return c.getHandshakeHash(); }, cipher);
    std::vector<uint8_t> tosign;
    std::string tls13_prefix = "                                                                TLS 1.3, server CertificateVerify\0";
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
        printf("%s:%d\n", __FILE__, __LINE__);
        break;
    }

    if (isValid) {
      state = TlsClientStateHandle::AuthenticationState::WaitingForFinished;
    } else {
      state = TlsClientStateHandle::AuthenticationState::Disconnected;
    }
  }

  std::vector<uint8_t> handleFinished(std::span<const uint8_t> message, std::span<const uint8_t> serverDigest) {
    if (state != TlsClientStateHandle::AuthenticationState::WaitingForFinished) {
      state = TlsClientStateHandle::AuthenticationState::Disconnected;
      return {};
    }

    std::vector<uint8_t> hmac = std::visit([&](auto& c){ return c.notifyServerFinished(message, serverDigest);}, cipher);
    if (hmac.empty()) {
      state = TlsClientStateHandle::AuthenticationState::Disconnected;
      return {};
    }

    std::vector<uint8_t> clientFinished;
    clientFinished.push_back(20);
    clientFinished.push_back(0);
    clientFinished.push_back(0);
    clientFinished.push_back(hmac.size());
    clientFinished.insert(clientFinished.end(), hmac.begin(), hmac.end());

    std::vector<uint8_t> rv = encrypt_message(clientFinished, 0x16);
    std::visit([&](auto& c) { c.switchToApplicationSecret(); }, cipher);
    state = TlsClientStateHandle::AuthenticationState::Operational;
    return rv;
  }

  std::vector<uint8_t> handleStartupMessage(uint16_t messageType, std::span<const uint8_t> message) {
    switch(state) {
      case TlsClientStateHandle::AuthenticationState::Operational:
      case TlsClientStateHandle::AuthenticationState::Disconnected:
        std::terminate();


      case TlsClientStateHandle::AuthenticationState::New:
      {
        std::vector<uint8_t> hello = clientHello(hostname, X25519(privkey, bignum<256>(9)));
        std::visit([&](auto& c){ std::span hs = hello; c.addHandshakeData(hs.subspan(5)); }, cipher);
        state = TlsClientStateHandle::AuthenticationState::WaitingForServerHello;
        return hello;
      }
      case TlsClientStateHandle::AuthenticationState::WaitingForServerHello:
      {
        std::visit([message = std::span<const uint8_t>(message)](auto& c){ c.addHandshakeData(message); }, cipher);
        if (messageType == 0x16) {
          auto helloState = handleServerHello(message, privkey);
          if (helloState == ServerHelloState::Invalid) {
            state = TlsClientStateHandle::AuthenticationState::Disconnected; 
          } else if (helloState == ServerHelloState::HelloRetry) {
            // TODO: add handling for hello retry here
            state = TlsClientStateHandle::AuthenticationState::Disconnected; 
          }
        } else {
          state = TlsClientStateHandle::AuthenticationState::Disconnected;
        }
        return {};
      }
      case TlsClientStateHandle::AuthenticationState::WaitingForEncryptedExtensions:
      {
        switch(messageType) {
          case 0x14: 
            // accept, but ignore. Compatibility message allowed by TLS 1.3 to inform middleboxes that we're going undercover.
            return {};
          case 0x1716:
          {
            std::visit([message = std::span<const uint8_t>(message)](auto& c){ c.addHandshakeData(message); }, cipher);
            reader r(message);
            uint8_t handshakeType = r.read8();
            if (handshakeType != 8) {
              state = TlsClientStateHandle::AuthenticationState::Disconnected;
              return {};
            }
            uint32_t size = r.read24be();
            std::span<const uint8_t> m = r.get(size);
            if (r.fail()) {
              state = TlsClientStateHandle::AuthenticationState::Disconnected;
              return {};
            }
            handleEncryptedExtensions(m);
            return {};
          }
          default:
            state = TlsClientStateHandle::AuthenticationState::Disconnected;
            return {};
        }
      }
      break;

      case TlsClientStateHandle::AuthenticationState::WaitingForCertificate:
      {
        std::visit([message = std::span<const uint8_t>(message)](auto& c){ c.addHandshakeData(message); }, cipher);
        if (messageType != 0x1716) {
          state = TlsClientStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        reader r(message);
        uint8_t handshakeType = r.read8();
        switch(handshakeType) {
          case 11: // Certificate request
            // TODO: implement certificate request handling for client
            return {};
          case 13:
          {
            uint32_t size = r.read24be();
            std::span<const uint8_t> m = r.get(size);
            if (r.fail()) {
              state = TlsClientStateHandle::AuthenticationState::Disconnected;
              return {};
            }
            handleCertificate(m);
            return {};
          }
          default:
            state = TlsClientStateHandle::AuthenticationState::Disconnected;
            return {};
        }
      }
        break;

      case TlsClientStateHandle::AuthenticationState::WaitingForCertificateVerify:
      {
        if (messageType != 0x1716) {
          state = TlsClientStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        reader r(message);
        uint8_t handshakeType = r.read8();
        if (handshakeType != 15) {
          state = TlsClientStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        uint32_t size = r.read24be();
        std::span<const uint8_t> m = r.get(size);
        if (r.fail()) {
          state = TlsClientStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        handleCertificateVerify(m);
        std::visit([message = std::span<const uint8_t>(message)](auto& c){ c.addHandshakeData(message); }, cipher);
      }
        return {};

      case TlsClientStateHandle::AuthenticationState::WaitingForFinished:
      {
        if (messageType != 0x1716) {
          state = TlsClientStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        reader r(message);
        uint8_t handshakeType = r.read8();
        if (handshakeType != 20) {
          state = TlsClientStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        uint32_t size = r.read24be();
        std::span<const uint8_t> m = r.get(size);
        if (r.fail()) {
          state = TlsClientStateHandle::AuthenticationState::Disconnected;
          return {};
        }
        return handleFinished(message, m);
      }
    }
  }

  std::vector<uint8_t> startupExchange(std::span<const uint8_t> data) {
    if (state == TlsClientStateHandle::AuthenticationState::Operational ||
        state == TlsClientStateHandle::AuthenticationState::Disconnected) {
      return {};
    }
    std::vector<uint8_t> rv;
    recvbuffer.insert(recvbuffer.end(), data.begin(), data.end());
    while (true) {
      reader r(recvbuffer);
      if (r.sizeleft() > 5) {
        uint16_t messageType = r.read8();
        uint16_t tlsver = r.read16be();
        if (tlsver != 0x0303) {
          state = TlsClientStateHandle::AuthenticationState::Disconnected;
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
              state = TlsClientStateHandle::AuthenticationState::Disconnected;
              return {};
            }
            while (!ddata.empty() && ddata.back() == 0) ddata.pop_back();
            if (ddata.empty()) {
              state = TlsClientStateHandle::AuthenticationState::Disconnected;
              return {};
            }
            messageType = 0x1700 | ddata.back();
            ddata.pop_back();
            messageBuffer = std::move(ddata);
          } else {
            messageBuffer = std::vector<uint8_t>(data.data(), data.data() + data.size());
          }
          memmove(recvbuffer.data(), recvbuffer.data() + 5 + size, recvbuffer.size() - size - 5);
          recvbuffer.resize(recvbuffer.size() - size - 5);
          auto feedback = handleStartupMessage(messageType, messageBuffer);
          rv.insert(rv.end(), feedback.begin(), feedback.end());
        }
      }
      break;
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
    if (state != TlsClientStateHandle::AuthenticationState::Operational) {
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
        state = TlsClientStateHandle::AuthenticationState::Disconnected;
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
          state = TlsClientStateHandle::AuthenticationState::Disconnected;
          return rv;
        }
        while (!ddata.empty() && ddata.back() == 0) ddata.pop_back();
        if (ddata.empty()) {
          state = TlsClientStateHandle::AuthenticationState::Disconnected;
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
          switch(handshakeType) {
          case 0x04: // New Session Ticket Message
            break;
          case 0x0d: // Post-Handshake Authentication
          case 0x18: // Key Update
          default:
            // invalid message
            state = TlsClientStateHandle::AuthenticationState::Disconnected;
            break;
          }
        }
          break;
        case 0x1715:
          if (message.size() < 2) {
            state = TlsClientStateHandle::AuthenticationState::Disconnected;
            break;
          }

          // Alert
          error = (TlsError)message[1];
          state = TlsClientStateHandle::AuthenticationState::Disconnected;
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
          state = TlsClientStateHandle::AuthenticationState::Disconnected;
          break;
        default:
          state = TlsClientStateHandle::AuthenticationState::Disconnected;
          break;
      }
    }
  }

  std::vector<uint8_t> send_encode(std::span<const uint8_t> data) {
    if (state != TlsClientStateHandle::AuthenticationState::Operational) return {};

    return encrypt_message(data, 0x17);
  }
};
/*
  std::string hostname;
  uint64_t currentTime;
  std::vector<uint8_t> recvbuffer;
  ec_value privkey = ec_value::random_private_key();
  std::variant<NullCipher, TLS13<GCM, AES<128>, SHA2<256>>, TLS13<GCM, AES<256>, SHA2<384>>> cipher;
  x509certificate cert;
*/
/*
  secret<Hash> secret;
  Hash handshake;
  Hash original;
  GCM<Cipher> s;
  GCM<Cipher> c;
*/

static_assert(sizeof(TlsClientState) < 4096);

namespace {
  template <typename T>
  struct SecureSpace {
    static const size_t allocsize = ((sizeof(T) * 32 + 4095) / 4096) * 4096;
    SecureSpace() {
      base = (char*)mmap(nullptr, allocsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED | MAP_NORESERVE, 0, 0);
      madvise((void*)base, allocsize, MADV_WIPEONFORK | MADV_DONTDUMP);
      mlock2((void*)base, allocsize, MLOCK_ONFAULT);
    }
    ~SecureSpace() {
      if (!base) return;
      if (used) {
        std::terminate();
      }
      munmap((void*)base, allocsize);
    }
    SecureSpace(SecureSpace&& rhs) {
      base = rhs.base;
      used = rhs.used;
      rhs.base = nullptr;
      rhs.used = 0;
    }
    const SecureSpace& operator=(SecureSpace&& rhs) {
      base = rhs.base;
      used = rhs.used;
      rhs.base = nullptr;
      rhs.used = 0;
      return *this;
    }
    volatile char* base = nullptr;
    uint32_t used = 0;
    void* take() {
      for (size_t n = 0; n < 32; n++) {
        if (used & (1 << n)) continue;
        used ^= 1 << n;
        return (void*)(base + n * sizeof(TlsClientState));
      }
      return nullptr;
    }
    bool put(void* p) {
      char* end = (char*)base + allocsize;
      if (p < base || p > end)
        return false;

      size_t index = ((char*)p - base) / sizeof(TlsClientState);
      volatile char* p2 = base + index * sizeof(TlsClientState);
      if (p != (char*)p2 || (used & (1 << index)) == 0)
        std::terminate();
      used ^= 1 << index;
      std::fill(p2, p2 + sizeof(TlsClientState), 0);
      return true;
    }
  };
  struct TlsStateAllocator {
    std::vector<SecureSpace<TlsClientState>> locations;
    void* allocate() {
      for (auto& s : locations) {
        if (s.used != 0xFFFFFFFF) {
          return s.take();
        }
      }
      locations.push_back({});
      return locations.back().take();
    }
    void free(void* p) {
      for (auto& s : locations) {
        if (s.put(p)) return;
      }
    }
  } stateAllocator;
}

TlsClientStateHandle::TlsClientStateHandle(std::string hostname, uint64_t currentTime) {
  state = new(stateAllocator.allocate()) TlsClientState(hostname, currentTime);
}

TlsClientStateHandle::~TlsClientStateHandle() {
  stateAllocator.free(state);
}

TlsClientStateHandle::AuthenticationState TlsClientStateHandle::getAuthenticationState() {
  return state->getAuthenticationState();
}

TlsError TlsClientStateHandle::getError() {
  return state->getError();
}

std::vector<uint8_t> TlsClientStateHandle::startupExchange(std::span<const uint8_t> data) {
  return state->startupExchange(data);
}

std::vector<uint8_t> TlsClientStateHandle::receive_decode(std::span<const uint8_t> data) {
  return state->receive_decode(data);
}

std::vector<uint8_t> TlsClientStateHandle::send_encode(std::span<const uint8_t> data) {
  return state->send_encode(data);
}


/**
TLS 1.3 flow:
1. Send ClientHello
2. Receive ServerHello
   (if HelloRetryRequest, go to 1)
2X Calculate handshake keys & switch to appropriate cipher
3. Receive EncryptedExtensions
4. (Receive CertificateRequest (if any))
5. Receive Certificate
6. Receive CertificateVerify
7. Receive Finished. ( Send EndOfEarlyData. Only if you sent any.)
8. (Send certificate + certificateverify, if requested.)
9. Send Finished.
9X Calculate application keys
*/

/*
TODO:
rsa_pkcs1_sha256 (certificate signature only)
rsa_pss_rsae_sha256 (certificate signature & certverify)
ecdsa_secp256r1_sha256 (?)

secp256r1 (key exchange)
*/

