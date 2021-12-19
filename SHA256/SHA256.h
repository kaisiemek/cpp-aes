//
// Created by Kai Siemek on 18.12.21.
//

#ifndef AES_CPP_SHA256_H
#define AES_CPP_SHA256_H

#include <vector>
#include <array>
#include <bit>
#include <string>
#include <cstddef>

#include "DataTypes.h"

namespace SHA {
  class SHA256
  {
  public:
    std::vector<uint8_t> m_data;
    std::vector<block> m_blocks;
  public:
    explicit SHA256(std::vector<uint8_t> input)
      : m_data(std::move(input)) {};

    std::string to_str();
    std::string to_block_str() const;
    std::string make_schedule_str(int block_no) const;


    void pad_data();
    void chunk_data();
    static schedule create_message_schedule(block ch);
    digest compress(const schedule &sched);

    // Internal SHA256 functions as defined in FIPS-180-4, 4.1.2
    // https://csrc.nist.gov/publications/detail/fips/180/4/final
    inline static word sigma_0(word w);
    inline static word sigma_1(word w);
    inline static word capital_sigma_0(word w);
    inline static word capital_sigma_1(word w);
    inline static word ch(word x, word y, word z);
    inline static word maj(word x, word y, word z);

    // SHA256 basic word operations as defined in FIPS-180-4, 3.2
    // https://csrc.nist.gov/publications/detail/fips/180/4/final
    static word rotr(word w, int n);
    inline static word shr(word w, int n);

  };
  constexpr std::array<word, 64> make_round_constants()
  {
    constexpr std::array<uint32_t, 64> rc{
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    std::array<word, 64> result{};
    std::transform(rc.begin(), rc.end(), result.begin(), [](uint32_t x)
    {
      return std::bit_cast<word>(flip_endianness(x));
    });

    return result;
  }

  const std::array<word, 64> round_constants = make_round_constants();
}


#endif //AES_CPP_SHA256_H
