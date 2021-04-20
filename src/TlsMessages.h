#pragma once

#include "X509Certificate.h"
#include "TlsEnums.h"

#include <writer.h>

#include <caligo/x25519.h>

#include <string>
#include <vector>
#include <set>
#include <cstdint>
#include <utility>

namespace Talos {

std::vector<uint8_t> serverHello(uint16_t cipherSuite, uint16_t group, std::span<const uint8_t> sessionId, std::span<const uint8_t> keyshare) {
  writer header;
  header.add16be(0x0303);
  for (uint8_t n = 0x70; n < 0x90; n++) {
    header.add8(n);
  }
  header.add8((uint8_t)sessionId.size());
  for (auto n : sessionId) {
    header.add8(n);
  }
  header.add16be(cipherSuite);
  header.add8(0);

  writer extensions;

  // Supported versions
  extensions.add16be(0x2B);
  extensions.add16be(0x02);
  extensions.add16be(0x0304);

  // Key share our key back
  extensions.add16be(0x33);
  extensions.add16be(0x24);
  extensions.add16be(group);
  extensions.add16be(0x20);
  extensions.add(keyshare);

  header.add16be(extensions.size());
  header.add(extensions);

  writer message;
  message.add8(0x16);
  message.add16be(0x0303);
  message.add16be(header.size() + 4);
  message.add8(0x02);
  message.add24be(header.size());
  message.add(header);
  return std::move(message);
}

std::vector<uint8_t> EncryptedExtensions(std::set<std::string> alpnProtocols) {
  writer exts;
  if (!alpnProtocols.empty()) {
    static std::vector<std::string> supported = { "http/1.1" };
    std::string selectedProtocol;
    for (auto proto : supported) {
      if (alpnProtocols.contains(proto)) {
        selectedProtocol = proto;
        break;
      }
    }

    if (not selectedProtocol.empty()) {
      exts.add16be((uint16_t)Tls::Extension::application_layer_protocol_negotiation);
      exts.add16be(selectedProtocol.size() + 3);
      exts.add16be(selectedProtocol.size() + 1);
      exts.add8(selectedProtocol.size());
      exts.add(selectedProtocol);
    }
  }
  writer ee;
  ee.add8(0x8);
  ee.add24be(exts.size() + 2);
  ee.add16be(exts.size());
  ee.add(exts);
  return std::move(ee);
}

std::vector<uint8_t> Certificate(std::vector<x509certificate> &mycert) {
  writer certs;
  for (auto &cert : mycert) {
    std::vector<uint8_t> certDer = cert.derCert;
    certs.add24be(certDer.size());
    certs.add(certDer);
    certs.add16be(0); // no extensions
  }
  writer header;
  header.add8(0x0b);
  header.add24be(certs.size() + 4);
  header.add8(0);
  header.add24be(certs.size());
  header.add(certs);
  return std::move(header);
}

std::vector<uint8_t> ServerCertificateVerify(std::set<uint16_t> allowedAlgorithms, PrivateKey& privkey, std::span<const uint8_t> hash) {
  static const std::vector<Tls13SignatureScheme> preferredSignatureTypes = {
    Tls13SignatureScheme::rsa_pss_rsae_sha256,
    Tls13SignatureScheme::rsa_pss_rsae_sha384,
    Tls13SignatureScheme::rsa_pss_rsae_sha512,
    Tls13SignatureScheme::rsa_pss_pss_sha256,
    Tls13SignatureScheme::rsa_pss_pss_sha384,
    Tls13SignatureScheme::rsa_pss_pss_sha512,
    Tls13SignatureScheme::rsa_pkcs1_sha256,
    Tls13SignatureScheme::rsa_pkcs1_sha384,
    Tls13SignatureScheme::rsa_pkcs1_sha512,
  };
  std::string tls13_prefix = "                                                                TLS 1.3, server CertificateVerify";
  tls13_prefix.push_back(0); // Do not move to the string literal above; there is *no* char[] constructor in std::string.
  std::vector<uint8_t> tosign;
  tosign.insert(tosign.end(), tls13_prefix.begin(), tls13_prefix.end());
  tosign.insert(tosign.end(), hash.begin(), hash.end());

  for (auto& type : preferredSignatureTypes) {
    if (not allowedAlgorithms.contains(type)) continue;

    std::vector<uint8_t> sig = privkey.sign(type, tosign);

    writer header;
    header.add8(0x0F);
    header.add24be(sig.size() + 4);
    header.add16be(type);
    header.add16be(sig.size());
    header.add(sig);
    return std::move(header);
  }

  return {};
}

std::vector<uint8_t> Finished(std::span<const uint8_t> hmac) {
  std::vector<uint8_t> finished;
  finished.push_back((uint8_t)Tls::Handshake::finished);
  finished.push_back(0);
  finished.push_back(0);
  finished.push_back(hmac.size());
  finished.insert(finished.end(), hmac.begin(), hmac.end());
  return finished;
}

std::vector<uint8_t> clientHello(const std::string& hostname, const Caligo::ec_value& pubkey) {
  writer header;
  header.add16be(0x0303);
  for (uint8_t n = 0; n < 32; n++) {
    header.add8(n);
  }
  header.add8(32);
  for (uint8_t n = 224; n != 0; n++) {
    header.add8(n);
  }

  writer suites;
  suites.add16be(0x1301); // aes128sha256
  suites.add16be(0x1302); // aes256sha384
//  suites.add16be(0x1303); // poly1305 (not actually)
  header.add16be(suites.size());
  header.add(suites);

  header.add8(0x01);
  header.add8(0x00);

  writer extensions;

  // Server Name Indication
  extensions.add16be(0x00); // server name
  extensions.add16be(hostname.size() + 5);
  extensions.add16be(hostname.size() + 3);
  extensions.add8(0x00);
  extensions.add16be(hostname.size());
  extensions.add(hostname);

  // Supported groups
  writer groups;
  groups.add16be(0x1D); // x25519
  groups.add16be(0x17); // secp256r1
  groups.add16be(0x18); // secp384r1 ????
  extensions.add16be(0x0a);
  extensions.add16be(groups.size() + 2);
  extensions.add16be(groups.size());
  extensions.add(groups);

  // Understood signature algorithms
  writer sigalgs;
  sigalgs.add16be(0x0403); // ECDSA-SECP256R1-SHA256
  sigalgs.add16be(0x0804); // RSA-PSS-RSAE-SHA256
  sigalgs.add16be(0x0401); // RSA-PKCS1-SHA256
  sigalgs.add16be(0x0503); // ECDSA-SECP384R1-SHA384
  sigalgs.add16be(0x0805); // RSA-PSS-RSAE-SHA384
  sigalgs.add16be(0x0501); // RSA-PKCS1-SHA384
  sigalgs.add16be(0x0806); // RSA-PSS-RSAE-SHA512
  sigalgs.add16be(0x0601); // RSA-PKCS1-SHA512
//  sigalgs.add16be(0x0201); // ulfheim special
  extensions.add16be(0x0d);
  extensions.add16be(sigalgs.size() + 2);
  extensions.add16be(sigalgs.size());
  extensions.add(sigalgs);

  // Key share our x25519 key
  extensions.add16be(0x33);
  extensions.add16be(0x26);
  extensions.add16be(0x24);
  extensions.add16be(0x1D);
  extensions.add16be(0x20);
  extensions.add(pubkey.as_bytes());

  // PSK key exchange modes
  extensions.add16be(0x2D);
  extensions.add16be(0x02);
  extensions.add8(0x01);
  extensions.add8(0x01);

  // Indicate we do TLS 1.3
  extensions.add16be(0x2B);
  extensions.add16be(0x03);
  extensions.add8(0x02);
  extensions.add16be(0x0304);
  
  header.add16be(extensions.size());
  header.add(extensions);

  writer message;
  message.add8(0x16);
  message.add16be(0x0301);
  message.add16be(header.size() + 4);
  message.add8(0x01);
  message.add24be(header.size());
  message.add(header);

  return std::move(message);
}

}


