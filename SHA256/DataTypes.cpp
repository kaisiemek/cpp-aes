//
// Created by Kai Siemek on 18.12.21.
//

#include "DataTypes.h"
#include <bit>
#include <algorithm>
#include <bitset>

// NOT operation
word operator~(word w1)
{
  std::transform(w1.begin(), w1.end(), w1.begin(), std::bit_not{});
  return w1;
}

// XOR operation
word operator^(word w1, word w2) {
  std::transform(w1.begin(), w1.end(), w2.begin(), w1.begin(), std::bit_xor{});
  return w1;
}

// AND operation
word operator&(word w1, word w2)
{
  std::transform(w1.begin(), w1.end(), w2.begin(), w1.begin(), std::bit_and{});
  return w1;
}

// PLUS mod 2^32 operation
word operator+(word w1, word w2) {
  // I hate this just as much as you do
  auto x {flip_endianness(std::bit_cast<uint32_t>(w1))};
  auto y {flip_endianness(std::bit_cast<uint32_t>(w2))};
  auto res {flip_endianness(x + y)};
  return std::bit_cast<word>(res);
}

std::ostream& operator<<(std::ostream& os, const word& w)
{
  for (const auto& b : w) {
    os << std::bitset<8>(b);
  }
  return os;
}
