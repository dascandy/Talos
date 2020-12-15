#pragma once

#include "x509_certificate.h"
#include <map>
#include <optional>

class Truststore {
public:
  static Truststore& Instance();
  std::optional<x509certificate*> get(const std::string& name);
  bool trust(std::vector<x509certificate> &untrustedCertificates, uint64_t currentTime);
  void addCertificate(x509certificate cert);
private:
  Truststore();
  std::map<std::string, x509certificate> trusted_certs;
};


