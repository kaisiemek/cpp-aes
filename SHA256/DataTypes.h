//
// Created by Kai Siemek on 18.12.21.
//

#ifndef AES_CPP_DATATYPES_H
#define AES_CPP_DATATYPES_H

#include <cstdint>
#include <array>
#include <iostream>
#include <bit>

// Sorry this doesn't have a namespace, the overloaded operators
// just do not want to work with the linker when namespaces are involved,
// will have to investigate at some point (I probably won't)

using word = std::array<uint8_t, 4>;
using block = std::array<uint8_t, 64>;
using schedule = std::array<word, 64>;
using digest = std::array<uint8_t, 256 / 8>;

word operator^(word w1, word w2);
word operator+(word w1, word w2);
word operator~(word w1);
word operator&(word w1, word w2);
std::ostream& operator<<(std::ostream& os, const word& w);

constexpr uint32_t flip_endianness(uint32_t val)
{
  // bit_cast to avoid annoying bitmasks + shifts, so we can just shift the
  // individual bytes around
  auto bytes {std::bit_cast<word>(val)};

  val = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | (bytes[3]);
  return val;
}

#endif //AES_CPP_DATATYPES_H
