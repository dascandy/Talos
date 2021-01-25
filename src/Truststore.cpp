#include "Truststore.h"

#include <fstream>
#include <optional>

namespace Talos {

Truststore& Truststore::Instance() {
  static Truststore store;
  return store;
}

Truststore::Truststore() {
  std::ifstream in("/etc/ssl/certs/ca-certificates.crt");
  std::vector<uint8_t> buffer;
  buffer.resize(std::filesystem::file_size("/etc/ssl/certs/ca-certificates.crt"));
  in.read((char*)buffer.data(), buffer.size());
  std::vector<x509certificate> certs = parseCertificatesPem(buffer);
  for (auto& cert : certs) {
    trusted_certs[cert.subject] = std::move(cert);
  }
}

std::optional<x509certificate*> Truststore::get(const std::string& name) {
  auto it = trusted_certs.find(name);
  if (it == trusted_certs.end()) return std::nullopt;
  return &it->second;
}

void Truststore::addCertificate(x509certificate cert) {
  trusted_certs[cert.subject] = std::move(cert);
}

// RFC 5280, chapter 6: Certificate validation
// Updated to support nonlinearity
// Goal: Determine whether or not untrustedCertificates[0] is trustable.
// For each of the currently untrusted certificates except the first, see if we have a corresponding trust anchor.
// If not, move to back of list & retry.
// For this certificate, check that:
//   Signature matches the issuer
//   Validity start is after the issuer started
//   Validity end is before the issuer ended
//   Current time is between validity start & validity end
// If they all match, add it to the localCertMap.
// If they are not all OK, discard certificate fully. No retries.
//
// When the certificates that are valid have been parsed (and those without a valid trust anchor discarded)
// For the final certificate, check that:
//   Signature matches the issuer
//   Validity start is after the issuer started
//   Validity end is before the issuer ended
//   Current time is between validity start & validity end
//
// construct the path to the applicable root
// then validate the policies from the root to the client certificate.
// if at any point these fail, return false
// return true;
bool Truststore::trust(std::vector<x509certificate> &untrustedCertificates, uint64_t currentTime) {
  std::map<std::string, x509certificate*> localCertMap;
  for (auto& [name, cert] : trusted_certs) {
    localCertMap[name] = &cert;
  }
  if (untrustedCertificates[0].validity_start > currentTime)
    return false;
  if (untrustedCertificates[0].validity_end < currentTime)
    return false;

  for (size_t n = 0; n < untrustedCertificates.size();) {
    if (localCertMap.find(untrustedCertificates[n].subject) != localCertMap.end() ||
        localCertMap.find(untrustedCertificates[n].issuer) == localCertMap.end()) {
      n++;
      continue;
    }

    x509certificate& issuer = *localCertMap.find(untrustedCertificates[n].issuer)->second;
    x509certificate& cert = untrustedCertificates[n];

    if (cert.verify(issuer)) {
      if (n == 0) {
        return true;
      }
      localCertMap[untrustedCertificates[n].subject] = &untrustedCertificates[n];
    } else {
      untrustedCertificates[n] = {};
    }

    n = 0;
  }
  return false;
}

}


