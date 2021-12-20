//
// Created by Kai Siemek on 16.12.21.
//

#include <iostream>
#include <sstream>
#include <iomanip>
#include <array>
#include <bit>

#include "Key128.h"
#include "../Constants.h"

using namespace AES;

const block& Key128::get_bytes() const
{
  return m_data;
}


// STATIC
std::deque<Key128> Key128::generate_key_schedule(Key128 initial_key)
{
  std::deque<Key128> keys;
  auto current_key {initial_key};

  for (int round{0}; keys.size() != SCHEDULE_KEY_NUM; ++round) {
    current_key = current_key.next_key(round);
    keys.push_back(current_key);
  }

  return keys;
}

// STRING/PRINT OPS
std::string Key128::to_str() const
{
  std::stringstream key_str;
  key_str << m_data;
  return key_str.str();
}

// PRIVATE
Key128 Key128::next_key(int round) const
{
  using std::array, std::bit_cast;

  if (round == 0) {
    return *this;
  }

  array<word, 4> result_words {};

  // Key generation uses 32 bit words, cast the key data (128 bit) into 4x32 bit words.
  auto words = bit_cast<array<word, 4>>(m_data);

  for (size_t i {0}; i < words.size(); ++i) {
    if (i == 0) {
      // For the first result XOR the word with the result of the g function of the last word
      result_words[0] = words[0] ^ g_function(words[3], round);
      continue;
    }
    // XOR the current value with the last result
    result_words[i] = words[i] ^ result_words[i - 1];
  }

  return Key128(bit_cast<block>(result_words));
}

word Key128::g_function(word data, int round)
{
  using std::array, std::bit_cast;
  // Round constants, https://en.wikipedia.org/wiki/AES_key_schedule#Rcon
  // rcon[i] => x^{index} mod x^8 + x^4 + x^3 + x + 1 (in AES GF256 finite field)
  constexpr array<byte, 11> rcon
    {
      0x00, // unused
      0x01, 0x02, 0x04, 0x08, 0x10,
      0x20, 0x40, 0x80, 0x1B, 0x36
    };

  auto data_bytes {bit_cast<array<byte, 4>>(data)};
  array<byte, 4> result {};

  // Compare "Understanding Cryptography" (Christof Paar) Figure 4.5
  // Shift bytes left by one, sub_bytes bytes with sboxes,
  for (size_t i {0}; i < result.size(); ++i) {
    result[i] = s_box[static_cast<uint8_t>(data_bytes[(i + 1) % result.size()])];

    // XOR only first byte of result with round constant (rcon)
    if (i == 0) {
      result[i] ^= rcon[round];
    }
  }

  return bit_cast<word>(result);
}

