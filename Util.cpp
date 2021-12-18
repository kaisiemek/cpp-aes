//
// Created by Kai Siemek on 17.12.21.
//

#include "Util.h"

#include <sstream>
#include <iomanip>
#include <bit>
#include <cstddef>

#include "Constants.h"

std::string AES::byte_to_string(std::byte byte)
{
  using namespace std;
  stringstream byte_str;

  byte_str << hex << uppercase << setfill('0') << setw(2) << +bit_cast<uint8_t>(byte);
  return byte_str.str();
}

std::ostream &AES::operator<<(std::ostream &os, const std::byte &x)
{
  os << byte_to_string(x);
  return os;
}

std::string AES::word_to_string(AES::word bytes)
{
  using namespace std;
  stringstream byte_str;

  byte_str << hex << uppercase;
  for (auto x : bytes) {
    byte_str << setfill('0') << setw(2) << +bit_cast<uint8_t>(x);
  }

  return byte_str.str();
}

std::string AES::block_to_string(AES::block bytes)
{
  using namespace std;
  stringstream byte_str;

  auto words {bit_cast<array<word, 4>>(bytes)};
  for (const auto& word : words) {
    byte_str << word_to_string(word) << ' ';
  }

  auto result_str = byte_str.str();
  result_str.pop_back(); // Remove last space
  return result_str;
}

AES::word AES::xor_word(AES::word x, AES::word y)
{
  word result {};

  for (size_t i {0}; i < result.size(); ++i) {
    result[i] = x[i] ^ y[i];
  }

  return result;
}

AES::word AES::operator^(const AES::word &w1, const AES::word &w2)
{
  return AES::xor_word(w1, w2);
}

std::byte AES::gf_256_mult(std::byte x_byte, std::byte y_byte)
{
  // Integral promotion to avoid overflows
  auto x {static_cast<uint16_t>(x_byte)};
  auto y {static_cast<uint16_t>(y_byte)};

  // Anything multiplied with 0 is 0, even in GF256 arithmetic :)
  if (x == 0 || y == 0) {
    return std::byte{0x00};
  }

  // Fancy calculations with log and exp tables, for more info on
  // the maths behind this refer to https://www.samiam.org/galois.html
  auto add = (galois_log_table[x] + galois_log_table[y]) % 255;
  return galois_exp_table[add];
}


