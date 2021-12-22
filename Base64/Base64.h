//
// Created by Kai Siemek on 21.12.21.
//

#ifndef AES_CPP_BASE64_H
#define AES_CPP_BASE64_H

#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <map>
#include <span>

class Base64
{
private:
  using triplet = std::span<const uint8_t, 3>;
  using quad = std::span<const char, 4>;

public:
  Base64() = delete;
  static std::string encode(const std::vector<uint8_t> &data);
  static std::vector<uint8_t> decode(std::string_view input_str);

private:
  static std::string encode_triplet(triplet trip, int padding = 0);
  static std::vector<uint8_t> decode_quad(quad qu);

  static std::map<char, uint8_t> make_decode_map();
  static inline constexpr std::array<char, 65> b64_table {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/',
    '=' // Padding
  };
};

#endif //AES_CPP_BASE64_H
