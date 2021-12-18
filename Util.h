//
// Created by Kai Siemek on 17.12.21.
//

#ifndef AES_CPP_UTIL_H
#define AES_CPP_UTIL_H

#include <array>
#include <string>
#include <iostream>

namespace AES
{
  // Consider making a class akin to std::byte
  using word = std::array<std::byte, 4>;
  using block = std::array<std::byte, 16>;
  using block_matrix = std::array<std::array<std::byte, 4>, 4>;

  std::string byte_to_string(std::byte byte);
  std::ostream& operator<<(std::ostream& os, const std::byte& x);

  std::string word_to_string(word bytes);
  std::string block_to_string(block bytes);

  // Utility functions to implement xor for two words
  word xor_word(word x, word y);
  word operator^(const word &w1, const word &w2);

  // Utility functions for GF256 multiplication with bytes
  std::byte gf_256_mult(std::byte x, std::byte y);
}

#endif //AES_CPP_UTIL_H
