#pragma once

#include "writer.h"
#include "caligo/x25519.h"
#include <string>
#include <vector>
#include <cstdint>
#include <utility>

std::vector<uint8_t> clientHello(const std::string& hostname, const ec_value& pubkey) {
  writer header;
  header.add16be(0x0303);
  header.addpadding(0x20, 0x00);
  header.add8(32);
  header.addpadding(32, 0);

  writer suites;
  suites.add16be(0x1301); // aes128sha256
//  suites.add16be(0x1302); // aes256sha384
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
//  groups.add16be(0x17); // secp256r1
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
