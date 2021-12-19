//
// Created by Kai Siemek on 19.12.21.
//

#ifndef AES_CPP_SHA256_H
#define AES_CPP_SHA256_H

#include <vector>
#include <array>
#include <bit>
#include <string>
#include <optional>
//#include <cstddef>

namespace SHA {
  // ========= Data Types =========
  using byte = uint8_t;
  using word = uint32_t;

  // Each block consists of 16 words = 64 Bytes = 512 Bits
  using block = std::array<byte, 64>;
  using schedule = std::array<word, 64>;

  // The final digest will be 8 words = 32 Bytes = 256 Bits
  using digest = std::array<byte, 32>;
  constexpr int COMPRESSION_LOOP_NO {64};

  class SHA256
  {
  private:
    static const std::array<word, 64> round_constants;
    static const std::array<word, 8> initial_hash_vals;

    std::vector<byte> m_data;
    std::array<word, 8> m_hash_vals; // h0-h7 in the spec
    std::optional<digest> m_digest; // final result
  public:
    explicit SHA256(std::vector<byte> input);
    digest create_digest();
    std::string digest_str();
  private:
    void pad_data();
    void compress(const schedule &sched);
    [[nodiscard]] std::vector<block> split_data() const;
    static schedule make_schedule(block blk);

    // Internal SHA256 functions as defined in FIPS-180-4, 4.1.2
    // https://csrc.nist.gov/publications/detail/fips/180/4/final
    inline static word sigma_0(word w);
    inline static word sigma_1(word w);
    inline static word capital_sigma_0(word w);
    inline static word capital_sigma_1(word w);
    inline static word ch(word x, word y, word z);
    inline static word maj(word x, word y, word z);

    // Helper function
    template<typename T>
    inline static T swap_endian(T val);
  };
}
#endif //AES_CPP_SHA256_H
