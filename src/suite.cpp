#include <variant>
#include "tls.h"
#include "sha2.h"
#include "hkdf.h"
#include "aes.h"
#include "ghash.h"
#include "gcm.h"
#include "writer.h"
#include "x25519.h"
#include "tls_messages.h"
#include "tcp_socket.h"
#include <cstdio>
#include "tls13.h"

struct NullCipher {
  std::vector<uint8_t> handshakeSoFar;
  void addHandshakeData(std::span<const uint8_t> data) {
    handshakeSoFar.insert(handshakeSoFar.end(), data.begin(), data.end());
  }
  std::vector<uint8_t> notifyServerFinished(std::span<const uint8_t>, std::span<const uint8_t>) {
    return {};
  }
  void updateTrafficSecrets() {
  }
  std::pair<std::vector<uint8_t>, bool> Decrypt(const std::span<const uint8_t> , const std::span<const uint8_t> , std::array<uint8_t, 16> ) {
    return { {}, false };
  }
  std::pair<std::vector<uint8_t>, std::array<uint8_t, 16>> Encrypt(const std::span<const uint8_t> , const std::span<const uint8_t> ) {
    return { {}, {} };
  }
};

struct tls::Impl {
  tcp_socket sock;
  std::vector<uint8_t> buffer;
  std::vector<uint8_t> recvbuffer;
  std::variant<NullCipher, TLS13<AES<128>, SHA256>, TLS13<AES<256>, SHA384>> cipher;
  Impl(tcp_socket sock)
  : sock(std::move(sock))
  {
    recvbuffer.reserve(8192);
  }
  future<std::pair<uint16_t, std::vector<uint8_t>>> receive() {
    while (true) {
      reader r(recvbuffer);
      if (r.sizeleft() > 5) {
        uint16_t messageType = r.read8();
        uint16_t tlsver = r.read16be();
        if (tlsver != 0x0303) co_return ERROR();
        uint16_t size = r.read16be();
        if (r.sizeleft() >= size) {
          auto data = r.get(size);
          if (messageType == 0x17) {
            auto [ddata, valid] = std::visit([&](auto& c){ 
              std::vector<uint8_t> aad;
              aad.resize(5);
              memcpy(aad.data(), recvbuffer.data(), 5);
              std::array<uint8_t, 16> tag;
              memcpy(tag.data(), data.data() + data.size() - 16, 16);
              return c.Decrypt(data.subspan(0, data.size() - 16), aad, tag);
            }, cipher);
            if (!valid) co_return ERROR();
            while (!ddata.empty() && ddata.back() == 0) ddata.pop_back();
            if (ddata.empty()) {
              fprintf(stderr, "No data!!\n");
              abort();
            }
            messageType = 0x1700 | ddata.back();
            ddata.pop_back();
            memmove(recvbuffer.data(), recvbuffer.data() + 5 + size, recvbuffer.size() - size - 5);
            recvbuffer.resize(recvbuffer.size() - size - 5);
            co_return { messageType, std::move(ddata) };
          } else {
            std::vector<uint8_t> msgbuffer{data.begin(), data.end()};
            memmove(recvbuffer.data(), recvbuffer.data() + 5 + size, recvbuffer.size() - size - 5);
            recvbuffer.resize(recvbuffer.size() - size - 5);
            co_return { messageType, std::move(msgbuffer) };
          }
        }
      }
      recvbuffer.resize(recvbuffer.size() + 4096);
      size_t bytesread = co_await sock.recvmsg(recvbuffer.data() + recvbuffer.size() - 4096, 4096);
      recvbuffer.resize(recvbuffer.size() - 4096 + bytesread);
    }
  }
  future<bool> handleServerHello(std::span<uint8_t> message, ec_value& privkey) {
    reader r(message);
    uint8_t handshakeType = r.read8();
    uint32_t size = r.read24be();
    if (handshakeType != 0x02 || size != message.size() - 4) co_return ERROR();

    uint16_t tlsver = r.read16be();
     if (tlsver != 0x0303) co_return ERROR();

    std::span<const uint8_t> serverRandom = r.get(32);
    static const std::array<const uint8_t, 32> helloRetryRequest = {
      0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 
      0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C, 
    };
    if (memcmp(helloRetryRequest.data(), serverRandom.data(), 32) == 0) co_return true;

    uint8_t sessSize = r.read8();
    r.get(sessSize); // ignore session ID; just some more TLS1.2 make pretend

    uint16_t cipherSuite = r.read16be();
    r.read8(); // no compression.
    uint16_t extLength = r.read16be();
    reader exts = r.get(extLength);
    if (r.fail()) co_return ERROR();
    while (exts.sizeleft()) {
      uint16_t key = exts.read16be();
      uint16_t size = exts.read16be();
      reader vals = exts.get(size);
      if (exts.fail()) co_return ERROR();
      switch(key) {
      case 0x33: // key share
      {
        // yay, we get the server's key too
        uint16_t keytype = vals.read16be();
        uint16_t keysize = vals.read16be();
        if (keytype != 0x1D) co_return ERROR();
        if (keysize != 0x20) co_return ERROR();
        ec_value serverpub = ec_value(vals.get(0x20));
        if (vals.fail()) co_return ERROR();
        ec_value sharedkey = X25519(privkey, serverpub);
        privkey.wipe();
        std::vector<uint8_t> sharedData = sharedkey.as_bytes();
        if (sharedkey == ec_value{0}) co_return ERROR();
        sharedkey.wipe();
        switch(cipherSuite) {
        case 0x1301: 
          cipher = TLS13<AES<128>, SHA256>(sharedData, std::move(std::get<NullCipher>(cipher).handshakeSoFar));
          break;
        case 0x1302: 
          cipher = TLS13<AES<256>, SHA384>(sharedData, std::move(std::get<NullCipher>(cipher).handshakeSoFar));
          break;
        default: 
          co_return ERROR();
        }
      }
        break;
      case 0x2b: // tls version
        tlsver = vals.read16be();
        break;
      default: 
        fprintf(stderr, "Found %02X\n", key);
        break;
//          co_return ERROR();
      }
    }
    if (tlsver != 0x0304) co_return ERROR();
    co_return false;
  }
  future<Void> handleEncryptedExtensions(std::span<const uint8_t> message) {
    // check for illegal ones or weird ones
    co_return {};
  }
  future<Void> handleCertificate(std::span<const uint8_t> message) {

    co_return {};
  }
  future<Void> handleCertificateVerify(std::span<const uint8_t> message) {

    co_return {};
  }
  future<Void> handleFinished(std::span<const uint8_t> message, std::span<const uint8_t> serverDigest) {
    std::vector<uint8_t> hmac = std::visit([&](auto& c){ return c.notifyServerFinished(message, serverDigest);}, cipher);
    std::vector<uint8_t> clientFinished;
    clientFinished.push_back(20);
    clientFinished.push_back(0);
    clientFinished.push_back(0);
    clientFinished.push_back(hmac.size());
    clientFinished.insert(clientFinished.end(), hmac.begin(), hmac.end());

    return sendmsg(clientFinished);
  }
  future<Void> initialize(std::string hostname) {
    ec_value privkey(ec_value::random());
    std::vector<uint8_t> hello = clientHello(hostname, X25519(privkey, bignum<8>(9)));
    std::visit([&](auto& c){ std::span hs = hello; c.addHandshakeData(hs.subspan(5)); }, cipher);
    co_await sock.sendmsg(hello);

    // Accept only server hello. Potentially retryrequest.
    {
      auto [msgtype, message] = co_await receive();
      std::visit([message = std::span<uint8_t>(message)](auto& c){ c.addHandshakeData(message); }, cipher);
      if (msgtype != 0x16) co_return ERROR();
      bool helloRetry = co_await handleServerHello(message, privkey);
      if (helloRetry) co_return ERROR();
    }

    do {
      auto [msgtype, message] = co_await receive();
      if (msgtype == 0x14) continue;
      if (msgtype != 0x1716) co_return ERROR();
      reader r(message);
      uint8_t handshakeType = r.read8();
      if (handshakeType != 8) co_return ERROR();
      std::visit([message = std::span<uint8_t>(message)](auto& c){ c.addHandshakeData(message); }, cipher);
      uint32_t size = r.read24be();
      std::span<const uint8_t> m = r.get(size);
      if (r.fail()) co_return ERROR();
      co_await handleEncryptedExtensions(m);
      break;
    } while(true);

    do {
      auto [msgtype, message] = co_await receive();

      if (msgtype != 0x1716) co_return ERROR();
      reader r(message);
      uint8_t handshakeType = r.read8();
      std::visit([message = std::span<uint8_t>(message)](auto& c){ c.addHandshakeData(message); }, cipher);
      if (handshakeType == 13) continue; // certificate request
      if (handshakeType != 11) co_return ERROR();
      uint32_t size = r.read24be();
      std::span<const uint8_t> m = r.get(size);
      if (r.fail()) co_return ERROR();
      co_await handleCertificate(m);
      break;
    } while(true);

    {
      auto [msgtype, message] = co_await receive();
      if (msgtype != 0x1716) co_return ERROR();
      reader r(message);
      uint8_t handshakeType = r.read8();
      if (handshakeType != 15) co_return ERROR();
      std::visit([message = std::span<uint8_t>(message)](auto& c){ c.addHandshakeData(message); }, cipher);
      uint32_t size = r.read24be();
      std::span<const uint8_t> m = r.get(size);
      if (r.fail()) co_return ERROR();
      co_await handleCertificateVerify(m);
    }

    {
      auto [msgtype, message] = co_await receive();
      if (msgtype != 0x1716) co_return ERROR();
      reader r(message);
      uint8_t handshakeType = r.read8();
      if (handshakeType != 20) co_return ERROR();
      uint32_t size = r.read24be();
      std::span<const uint8_t> m = r.get(size);
      if (r.fail()) co_return ERROR();
      co_await handleFinished(message, m);
    }

    co_return {};
  }
  future<size_t> recvmsg(std::span<uint8_t> s) {
    if (!buffer.empty()) {
      size_t frombuffer = std::min(s.size(), buffer.size());
      memcpy(s.data(), buffer.data(), frombuffer);
      memmove(buffer.data(), buffer.data() + frombuffer, buffer.size() - frombuffer);
      buffer.resize(buffer.size() - frombuffer);
      co_return frombuffer;
    }
    auto [type, msg] = co_await receive();
    if (type != 0x1717) co_return ERROR();
    size_t copynow = std::min(msg.size(), s.size());
    memcpy(s.data(), msg.data(), copynow);
    buffer = std::vector<uint8_t>(msg.data() + copynow, msg.data() + msg.size());
    co_return copynow;
  }
  future<Void> sendmsg(std::span<const uint8_t> msg) {
    std::vector message(msg.begin(), msg.end());
    message.push_back(0x17);
    auto [emsg, tag] = std::visit([&message](auto& c){ return c.Encrypt(message, {});}, cipher);
    message.resize(16+6+msg.size());
    message[0] = 0x17;
    message[1] = 0x03;
    message[2] = 0x03;
    message[3] = ((message.size() >> 8) & 0xFF);
    message[4] = (message.size() & 0xFF);
    memcpy(message.data() + 5, emsg.data(), emsg.size());
    memcpy(message.data() + 5 + emsg.size(), tag.data(), tag.size());
    co_await sock.sendmsg(message);
    co_return {};
  }
};

tls::tls(tcp_socket sock)
: impl(new Impl(std::move(sock)))
{}

future<Void> tls::initialize(std::string hostname) {
  return impl->initialize(hostname);
}

future<size_t> tls::recvmsg(std::span<uint8_t> s) {
  return impl->recvmsg(s);
}

future<Void> tls::sendmsg(std::span<const uint8_t> msg) {
  return impl->sendmsg(msg);
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

