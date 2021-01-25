#pragma once

#include <string>
#include <unordered_set>
#include "asn1.h"
#include <caligo/bignum.h>
#include <caligo/rsa.h>
#include <caligo/rsapss.h>

namespace Talos {

using x509date = uint64_t;
using x509id = std::vector<uint8_t>;

struct x509name {
  std::string common_name;
  std::string country;
  std::string emailaddress;
  std::string givenname;
  std::string locality;
  std::string organization;
  std::string organizationIdentifier;
  std::string organizationalunit;
  std::string serialnumber;
  std::string state;
  std::string streetaddress;
  std::string surname;
  std::string title;

  friend std::string to_string(const x509name& name) {
    std::string accum;
    if (!name.serialnumber.empty()) accum += "S#=" + name.serialnumber + " ";
    if (!name.country.empty()) accum += "C=" + name.country + " ";

    if (!name.locality.empty()) accum += "L=" + name.locality + " ";
    if (!name.streetaddress.empty()) accum += "STREET=" + name.streetaddress + " ";
    if (!name.state.empty()) accum += "ST=" + name.state + " ";

    if (!name.emailaddress.empty()) accum += "E=" + name.emailaddress + " ";
    if (!name.givenname.empty()) accum += "GN=" + name.givenname + " ";
    if (!name.surname.empty()) accum += "SN=" + name.surname + " ";
    if (!name.title.empty()) accum += "T=" + name.title + " ";

    if (!name.organization.empty()) accum += "O=" + name.organization + " ";
    if (!name.organizationIdentifier.empty()) accum += "OI=" + name.organizationIdentifier + " ";
    if (!name.organizationalunit.empty()) accum += "OU=" + name.organizationalunit + " ";

    if (!name.common_name.empty()) accum += "CN=" + name.common_name + " ";

    if (!accum.empty()) accum.pop_back();
    return accum;
  }
};

struct object_id {
  struct PublicKey { // namespace, but can't put namespace here
    static object_id RsaEncryption;
    static object_id RsaSsaPss;
    static object_id EcPublicKey;
    static object_id X25519;
    static object_id X448;
  };
  struct X509NameParts {
    static object_id CommonName;
    static object_id Surname;
    static object_id SerialNumber;
    static object_id Country;
    static object_id Locality;
    static object_id StateOrProvince;
    static object_id StreetAddress;
    static object_id Organization;
    static object_id OrganizationIdentifier;
    static object_id OrganizationalUnit;
    static object_id Title;
    static object_id GivenName;
    static object_id EmailAddress;
  };

  struct SignatureType {
    static object_id EcdsaSHA256;
    static object_id EcdsaSHA384;
    static object_id EcdsaSHA512;
    static object_id RsaSHA256;
    static object_id RsaSHA384;
    static object_id RsaSHA512;
  };

  object_id() 
  {
  }
  object_id(std::span<const uint8_t> data)
  : data(data.data(), data.data() + data.size())
  {}
  std::vector<uint8_t> data;
  bool operator==(const object_id& o) const = default;
};

struct PublicKey {
  virtual ~PublicKey() = default;
  virtual bool validateSignature(std::vector<uint8_t>, std::span<const uint8_t>) const = 0;
  virtual bool validateRsaSsaPss(std::span<const uint8_t> message, std::span<const uint8_t> sig) const = 0;
};

struct RsaPubkey : PublicKey {
  rsa_public_key<4096> pubkey;
  RsaPubkey(rsa_public_key<4096> pubkey)
  : pubkey(pubkey)
  {}
  bool validateSignature(std::vector<uint8_t>, std::span<const uint8_t>) const override;
  bool validateRsaSsaPss(std::span<const uint8_t> message, std::span<const uint8_t> sig) const override;
};

struct PrivateKey {
  virtual std::vector<uint8_t> signPkcs15(std::span<const uint8_t> message) const = 0;
  virtual std::vector<uint8_t> signRsaSsaPss(std::span<const uint8_t> message) const = 0;
};

struct RsaPrivateKey : PrivateKey {
  rsa_private_key<4096> privkey;
  RsaPrivateKey(rsa_private_key<4096> privkey)
  : privkey(privkey)
  {}
  std::vector<uint8_t> signPkcs15(std::span<const uint8_t> message) const override;
  std::vector<uint8_t> signRsaSsaPss(std::span<const uint8_t> message) const override;
};

template <size_t Bits, typename Hash, typename MGF>
bool validateRsaSsaPss(const rsa_public_key<Bits>& pubkey, std::span<const uint8_t> message, std::span<const uint8_t> sig) {
  if (sig.size() > (Bits / 8)) return false;
  std::vector<uint8_t> nsig(sig.data(), sig.data() + sig.size());
  std::reverse(nsig.begin(), nsig.end());
  auto sig_bytes = rsaep(pubkey, bignum<Bits>(nsig)).as_bytes();
  sig_bytes.resize(sig.size());
  std::reverse(sig_bytes.begin(), sig_bytes.end());

  return Caligo::EMSA_PSS_VERIFY<Hash, MGF::hashsize, MGF>(message, sig_bytes);
}

struct x509certificate {
  std::vector<uint8_t> derCert;
  bignum<128> serialNumber;
  // algorithm identifier?
  std::unordered_set<std::string> fqdns;
  std::string subject;
  std::string issuer;

  x509date validity_start;
  x509date validity_end;

  // public key, somehow
  std::unique_ptr<PublicKey> pubkey; // local ptr?

  // v3 extensions


  bool appliesTo(const std::string& fqdn) {
    return fqdns.find(fqdn) != fqdns.end();
  }
  bool verify(x509certificate& issuer);
};

enum class CertificateFormat {
  Der,
  Pem,
};

std::vector<x509certificate> parseCertificatesPem(std::span<const uint8_t> in);
x509certificate parseCertificate(std::span<const uint8_t> in, CertificateFormat format = CertificateFormat::Der);

}


