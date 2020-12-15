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
#include "TlsState.h"

std::string to_string(TlsError error) {
  (void)error;
  return "FAIL";
}

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
        return (void*)(base + n * sizeof(TlsState));
      }
      return nullptr;
    }
    bool put(void* p) {
      char* end = (char*)base + allocsize;
      if (p < base || p > end)
        return false;

      size_t index = ((char*)p - base) / sizeof(TlsState);
      volatile char* p2 = base + index * sizeof(TlsState);
      if (p != (char*)p2 || (used & (1 << index)) == 0)
        std::terminate();
      used ^= 1 << index;
      std::fill(p2, p2 + sizeof(TlsState), 0);
      return true;
    }
  };
  struct TlsStateAllocator {
    std::vector<SecureSpace<TlsState>> locations;
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

TlsStateHandle::TlsStateHandle(std::string hostname, uint64_t currentTime) {
  state = new(stateAllocator.allocate()) TlsState(hostname, currentTime);
}

TlsStateHandle::~TlsStateHandle() {
  stateAllocator.free(state);
}

TlsStateHandle::AuthenticationState TlsStateHandle::getAuthenticationState() {
  return state->getAuthenticationState();
}

TlsError TlsStateHandle::getError() {
  return state->getError();
}

std::vector<uint8_t> TlsStateHandle::startupExchange(std::span<const uint8_t> data) {
  return state->startupExchange(data);
}

std::vector<uint8_t> TlsStateHandle::receive_decode(std::span<const uint8_t> data) {
  return state->receive_decode(data);
}

std::vector<uint8_t> TlsStateHandle::send_encode(std::span<const uint8_t> data) {
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

