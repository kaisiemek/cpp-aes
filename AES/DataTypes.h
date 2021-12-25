//
// Created by Kai Siemek on 20.12.21.
//

#ifndef AES_CPP_DATATYPES_H
#define AES_CPP_DATATYPES_H

#include <cstdint>
#include <array>
#include <ostream>

namespace AES {
  using byte = uint8_t;
  using word = uint32_t;
  using block = std::array<byte, 16>;
  using round_key = std::array<byte, 16>;
  using matrix = std::array<std::array<byte, 4>, 4>;

  // GF256 multiplication as needed for the mix_columns step.
  byte gf_256_mult(byte x, byte y);
}

// Convenience operator for debugging purposes, prints the block
// as hex block
std::ostream& operator<<(std::ostream& os, const AES::block& x);

#endif //AES_CPP_DATATYPES_H
