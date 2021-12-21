//
// Created by Kai Siemek on 17.12.21.
//

#include "StateMatrix.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <bit>

#include "../Constants.h"

using namespace AES;

StateMatrix::StateMatrix(block block_data)
: m_data {std::bit_cast<matrix>(block_data)}
{ }

block StateMatrix::get_data() const
{
  return std::bit_cast<block>(m_data);
}

void StateMatrix::add_round_key(const round_key &key)
{
  using std::array, std::bit_cast;

  // Copy the matrix data into a flat array
  auto byte_cpy = bit_cast<block>(m_data);

  // XOR each key and data byte, assign it to result
  std::transform(byte_cpy.begin(), byte_cpy.end(), key.begin(), byte_cpy.begin(), std::bit_xor{});

  // Re-package the flat array as matrix
  m_data = bit_cast<matrix>(byte_cpy);
}

// ENCRYPTION STEPS
void StateMatrix::sub_bytes()
{
  for (auto& col : m_data) {
    for (auto& cell : col) {
      cell = s_box[cell];
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
  using std::array, std::bit_cast;

  // Matrix with which the state matrix is multiplied in GF256
  static constexpr matrix mc{
    {
       {2, 1, 1, 3},
       {3, 2, 1, 1},
       {1, 3, 2, 1},
       {1, 1, 3, 2},
     }
  };

  auto tmp = m_data;

  // Kind of messy matrix multiplication in GF256
  // please refer to https://en.wikipedia.org/wiki/Rijndael_MixColumns
  // and https://www.samiam.org/galois.html for the GF256 math.
  for (size_t col {0}; col < 4; ++col) {
    for (size_t row {0}; row < 4; ++row) {
      m_data[col][row] = 0x00;
      for (size_t entry {0}; entry < 4; ++entry) {
        m_data[col][row] ^= gf_256_mult(mc[entry][row], tmp[col][entry]);
      }
    }
  }
}

// DECRYPTION STEPS
void StateMatrix::inv_sub_bytes()
{
  for (auto& col : m_data) {
    for (auto& cell : col) {
      cell = inverse_s_box[cell];
    }
  }
}

void StateMatrix::inv_shift_rows()
{
  using std::array;
  // First row is not shifted, second by one bytes to the right, etc.
  // Cyclic shift, so the shifts in shift_rows + inv_shift_rows add up to 0 mod 4
  static constexpr array<size_t, 4> shifts {0, 1, 2, 3};

  auto tmp = m_data;

  for (size_t row {0}; row < m_data.size(); ++row) {
    for (size_t col {0}; col < m_data[row].size(); ++col) {
      // Add shifts[row] to the column index, wrap around at 4
      m_data[(col + shifts[row]) % m_data.size()][row] = tmp[col][row];
    }
  }
}

void StateMatrix::inv_mix_columns()
{
  using std::array, std::bit_cast;

  // Matrix with which the state matrix is multiplied in GF256
  // Inverse matrix of the matrix in mix_columns()
  static constexpr matrix inverse_mc {
    {
      {0x0E, 0x09, 0x0D, 0x0B},
      {0x0B, 0x0E, 0x09, 0x0D},
      {0x0D, 0x0B, 0x0E, 0x09},
      {0x09, 0x0D, 0x0B, 0x0E},
    }
  };

  auto tmp = m_data;

  // Kind of messy matrix multiplication in GF256
  // please refer to https://en.wikipedia.org/wiki/Rijndael_MixColumns
  // and https://www.samiam.org/galois.html for the GF256 math.
  for (size_t col {0}; col < 4; ++col) {
    for (size_t row {0}; row < 4; ++row) {
      m_data[col][row] = byte{0};
      for (size_t entry {0}; entry < 4; ++entry) {
        m_data[col][row] ^= gf_256_mult(inverse_mc[entry][row], tmp[col][entry]);
      }
    }
  }
}

// STRING/PRINT OPS
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