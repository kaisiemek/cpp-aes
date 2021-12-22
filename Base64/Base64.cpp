//
// Created by Kai Siemek on 21.12.21.
//

#include "Base64.h"

#include <sstream>

// PUBLIC INTERFACE
std::string Base64::encode(const std::vector<uint8_t> &data)
{
  std::stringstream b64_str;

  int padding { data.size() % 3 == 0 ? 0 : static_cast<int>(3 - (data.size() % 3))};

  for(auto it {data.cbegin()}; std::distance(it, data.cend()) >= 3; it += 3) {
    b64_str << encode_triplet(triplet{it, 3});
  }

  if (padding != 0) {
    std::vector<uint8_t> padded_vec(data.cend() - (3 - padding), data.cend());
    // Fill rest up with 0s
    padded_vec.resize(3);
    b64_str << encode_triplet(triplet{padded_vec.cbegin(), 3}, padding);
  }

  return b64_str.str();
}

std::vector<uint8_t> Base64::decode(std::string_view input_str)
{
  if (input_str.length() % 4 != 0) {
    throw std::length_error{"The input string (view) length must be a multiple of 4."};
  }

  std::vector<uint8_t> output;
  for(auto it {input_str.cbegin()}; it != input_str.cend(); it += 4) {
    std::span<const char, 4> quad {it, 4};
    std::vector<uint8_t> quad_data {decode_quad(quad)};
    output.insert(output.end(), quad_data.cbegin(), quad_data.cend());
  }

  return output;
}

// PRIVATE HELPERS
std::string Base64::encode_triplet(triplet trip, int padding)
{
  // 6 least significant bits
  static constexpr uint8_t bitmask{0b0011'1111};
//  std::cout << padding << std::endl;
  // Need a datatype large enough to hold 3 uint8_ts = 24 bits
  // Concatenate the values by bit shifting each uint8_t and ORing the final value.
  uint32_t concatenation{0};
  for (int i{0}; i < trip.size(); ++i) {
    concatenation |= trip[i] << (16 - (i * 8));
  }

  std::stringstream triplet_str;
  // For each sextet -> cast to uint8_t and use as index for base64 table,
  // assign to corresponding result entry
  for (int i{0}; i < 4; ++i) {
    // Either use padding index (64) or calculate the table index
    // by getting the i-th sextet from the concatenated value and using it
    // as table index.
    auto table_index {
      (i > 3 - padding) ? 64 : concatenation >> (18 - (i * 6)) & bitmask
    };
    triplet_str << b64_table[table_index];
  }

  return triplet_str.str();
}

  std::vector<uint8_t> Base64::decode_quad(quad qu)
  {
    static constexpr uint8_t bitmask {0xFF};
    // Make map once, map can't be constexpr yet :(
    static std::map<char, uint8_t> decode_map {make_decode_map()};

    uint32_t concatenation {0};
    uint8_t padding {0};
    for (int i {0}; i < qu.size(); ++i) {
      // Skip the padding, leave at 0 in concatenated value
      if (qu[i] == '=') {
        ++padding;
        continue;
      }
      // Shift the current characters corresponding sextet to the correct location
      concatenation |= static_cast<uint32_t>(decode_map.at(qu[i])) << (18 - 6 * i);
    }

    // Recover individual bytes from concatenated sextets by bit shifting.
    std::vector<uint8_t> result {};
    for (int i {0}; i < 3 - padding; ++i) {
      result.push_back((concatenation >> (16 - i * 8)) & bitmask);
    }

    return result;
  }

  std::map<char, uint8_t> Base64::make_decode_map()
  {
    std::map<char, uint8_t> decode_map;

    for (int i {0}; i < b64_table.size(); ++i) {
      decode_map[b64_table[i]] = i;
    }

    return decode_map;
  }

