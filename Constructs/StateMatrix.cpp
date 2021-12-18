//
// Created by Kai Siemek on 17.12.21.
//

#include "StateMatrix.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <bit>
#include <cstddef>

#include "../Util.h"
#include "../Constants.h"

using namespace AES;

StateMatrix::StateMatrix(block block_data)
: m_data {std::bit_cast<block_matrix>(block_data)}
{ }

void StateMatrix::add_key(Key128 key)
{
  using std::array, std::byte, std::bit_cast;

  // Copy the matrix data into a flat array
  auto byte_cpy = bit_cast<block>(m_data);
  auto key_data = key.get_bytes();

  // XOR each key and data byte, assign it to result
  block tmp{};
  std::transform(byte_cpy.begin(), byte_cpy.end(), key_data.begin(), tmp.begin(), std::bit_xor{});

  // Re-package the flat array as matrix
  m_data = bit_cast<block_matrix>(tmp);
}

void StateMatrix::substitute()
{
  for (auto& col : m_data) {
    for (auto& cell : col) {
      cell = s_box[static_cast<uint8_t>(cell)];
    }
  }
}

void StateMatrix::shift_rows()
{
  using std::array;
  // First row is not shifted, second by three bytes to the right, etc.
  static constexpr array<size_t, 4> shifts {0, 3, 2, 1};

  auto tmp = m_data;

  for (size_t row {0}; row < m_data.size(); ++row) {
    for (size_t col {0}; col < m_data[row].size(); ++col) {
      // Add shifts[row] to the column index, wrap around at 4
      m_data[(col + shifts[row]) % m_data.size()][row] = tmp[col][row];
    }
  }
}

void StateMatrix::mix_columns()
{
  using std::array, std::bit_cast, std::byte;

  // Matrix with which the state matrix is multiplied in GF256
  static constexpr auto mc = bit_cast<block_matrix>(array<array<uint8_t, 4>, 4>
    {{
       {2, 1, 1, 3},
       {3, 2, 1, 1},
       {1, 3, 2, 1},
       {1, 1, 3, 2},
     }}
  );

  auto tmp = m_data;

  // Kind of messy matrix multiplication in GF256
  // please refer to https://en.wikipedia.org/wiki/Rijndael_MixColumns
  // and https://www.samiam.org/galois.html for the GF256 math.
  for (size_t col {0}; col < 4; ++col) {
    for (size_t row {0}; row < 4; ++row) {
      m_data[col][row] = byte{0};
      for (size_t entry {0}; entry < 4; ++entry) {
        m_data[col][row] ^= gf_256_mult(mc[entry][row], tmp[col][entry]);
      }
    }
  }
}

block StateMatrix::get_data() const
{
  return std::bit_cast<block>(m_data);
}

std::string StateMatrix::to_string() const
{
  std::stringstream mat_str;

  for (size_t row {0}; row < m_data.size(); ++row) {
    mat_str << "| ";
    for (size_t col {0}; col < m_data[row].size(); ++col) {
      mat_str << m_data[col][row] << " ";
    }
    mat_str << "|\n";
  }

  return mat_str.str();
}

std::ostream& operator<<(std::ostream& os, const StateMatrix& mat)
{
  os << mat.to_string();
  return os;
}
