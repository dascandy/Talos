#pragma once

#include <span>
#include <utility>
#include <cstdint>
#include <cstddef>

namespace Talos {

enum class asn1_id {
  boolean = 1,
  integer = 2,
  bit_string = 3,
  octet_string = 4,
  null = 5,
  object = 6,
  utf8string = 12,
  printablestring = 19,
  utctime = 23,
  generalizedtime = 24,
  sequence = 48,
  set = 49,
  array0 = 160,
  array1 = 161,
  array2 = 162,
  array3 = 163,
  array4 = 164
};

struct asn1_view {
  std::span<const uint8_t> data;
  size_t offset = 0;
  asn1_view(std::span<const uint8_t> data) 
  : data(data)
  {}
  std::pair<asn1_id, std::span<const uint8_t>> read() {
    asn1_id id = (asn1_id)data[offset++];
    size_t size = data[offset++];
    if (size & 0x80) {
      size_t bytes = size & 0x7F;
      size = 0;
      for (; bytes --> 0;) {
        size = (size << 8) + data[offset++];
      }
    }
    size_t off = offset;
    offset += size;
    return { id, std::span<const uint8_t>(data.data() + off, data.data() + off + size) };
  }
  asn1_id peek() {
    return (asn1_id)data[offset];
  }
  bool empty() {
    return offset == data.size();
  }
};

}


