//
// Created by Kai Siemek on 20.12.21.
//

#include "Key.h"

#include <cstring>
#include "../../SHA256/SHA256.h"

AES::Key::Key(std::array<byte, AES128_KEY_WIDTH> data)
  : m_data(data.begin(), data.end())
{
  set_key_parameters(KeySize::AES128);
  key_expansion();
}

AES::Key::Key(std::array<byte, AES192_KEY_WIDTH> data)
  : m_data(data.begin(), data.end())
{
  set_key_parameters(KeySize::AES192);
  key_expansion();
}

AES::Key::Key(std::array<byte, AES256_KEY_WIDTH> data)
  : m_data(data.begin(), data.end())
{
  set_key_parameters(KeySize::AES256);
  key_expansion();
}

AES::Key::Key(std::string_view password, AES::KeySize bitsize)
{
  set_key_parameters(bitsize);

  // Hash the password to create 256 bits of data from the password
  std::vector<SHA::byte> pw_data(password.begin(), password.end());
  auto digest_data{SHA::SHA256(pw_data).create_digest()};

  // Use 128-256 bits of the SHA256 digest as key data, depending on chosen KeySize
  // Discard the rest of the data.
  // !! DO NOT DO THIS IN ACTUAL APPLICATIONS !!!
  // Use something like PBKDF2, maybe bcrypt and salt it!
  // More information https://security.stackexchange.com/questions/38828/
  // I used SHA here because I was interested in the SHA256 algorithm and wanted to implement it.
  // Given the educational nature of this project it seemed like a fine choice.
  int bytes {m_key_width};
  m_data = {digest_data.begin(), digest_data.begin() + bytes};

  key_expansion();
}

// Refer to FIPS 197, Section 5.2 "Key Expansion"
void AES::Key::key_expansion()
{
  int words_needed {m_round_keys_needed * static_cast<int>(sizeof(round_key) / sizeof(word))};
  int round_width {m_key_width / 4};

  // Copy the first 128/192 bit = 4/6 words into our expanded data vector
  m_expanded_data = std::vector<word>(m_data.begin(), m_data.end());
  m_expanded_data.resize(words_needed);

  for (int i {0 + round_width}; i < words_needed; ++i) {
    m_expanded_data[i] = m_expanded_data[i - round_width];

    // At the beginning of each key expansion round XOR the previous value with the
    // last word of the previous round permuted by the rot_word function.
    if (i % round_width == 0) {
      m_expanded_data[i] ^= rot_word(m_expanded_data[i - 1], i / round_width);
    } else if ((i % round_width == 4) && (round_width == AES256_KEY_WIDTH / 4)) {
      // If we're at the fourth byte of a round and when using AES256 call
      m_expanded_data[i] ^= sub_word(m_expanded_data[i - 1]);
    } else {
      // If we're not at the beginning of a round just xor with the previous value.
      m_expanded_data[i] ^= m_expanded_data[i - 1];
    }
  }
}

// Refer to FIPS 197, Section 5.2 "Key Expansion"
AES::word AES::Key::rot_word(AES::word w, int round)
{
  using std::array, std::bit_cast;
  // rcon[i] => x^{index} mod x^8 + x^4 + x^3 + x + 1 (in AES GF256 finite field)
  // https://en.wikipedia.org/wiki/AES_key_schedule#Rcon
  static constexpr array<byte, 11> rcon {
      0x00, // unused
      0x01, 0x02, 0x04, 0x08, 0x10,
      0x20, 0x40, 0x80, 0x1B, 0x36
  };

  auto word_bytes {reinterpret_cast<byte*>(&w)};
  array<byte, 4> res {};

  // Cyclic permutation [a0, a1, a2, a3] -> [a1, a2, a3, a0]
  for (size_t i {0}; i < res.size(); ++i) {
    res[i] = s_box[word_bytes[(i + 1) % res.size()]];
  }

  // Xor the first byte with round constant
  res[0] ^= rcon[round];

  return bit_cast<word>(res);
}

std::deque<AES::round_key> AES::Key::generate_key_schedule()
{
  std::vector<round_key> vec(m_round_keys_needed);
  std::memcpy(vec.data(), m_expanded_data.data(), vec.size() * sizeof(round_key));

  return std::deque<AES::round_key> {vec.begin(), vec.end()};
}

void AES::Key::set_key_parameters(AES::KeySize keysize)
{
  switch (keysize) {
    case KeySize::AES128:
      m_key_width = AES128_KEY_WIDTH;
      m_round_keys_needed = AES128_ENCRYPTION_ROUNDS + 1;
      break;
    case KeySize::AES192:
      m_key_width = AES192_KEY_WIDTH;
      m_round_keys_needed = AES192_ENCRYPTION_ROUNDS + 1;
      break;
    case KeySize::AES256:
      m_key_width = AES256_KEY_WIDTH;
      m_round_keys_needed = AES256_ENCRYPTION_ROUNDS + 1;
      break;
  }
}

AES::word AES::Key::sub_word(AES::word w)
{
  using std::array, std::bit_cast;
  auto word_bytes {reinterpret_cast<byte*>(&w)};
  array<byte, 4> res {};

  // Perform byte substitution on each individual byte of the word
  for (size_t i {0}; i < res.size(); ++i) {
    res[i] = s_box[word_bytes[i]];
  }

  return bit_cast<word>(res);
}

int AES::Key::get_supported_round_number() const
{
  // One round number less
  return m_round_keys_needed - 1;
}
