//
// Created by Kai Siemek on 25.12.21.
//

#include "AES.h"

namespace AES {
  // BOTH ENCRYPTION & DECRYPTION
  void AES::add_round_key(std::span<const byte, 16> round_key)
  {
    std::transform(
      m_curblk.begin(), m_curblk.end(),
      round_key.begin(), m_curblk.begin(),
      std::bit_xor{}
    );
  }

  // ENCRYPTION OPERATIONS
  void AES::sub_bytes()
  {
    for (auto& b : m_curblk) {
      b = s_box[b];
    }
  }

  void AES::shift_rows()
  {
    // First row is not shifted, second by three bytes to the right, etc.
    static constexpr std::array<size_t, 4> shifts {0, 3, 2, 1};

    // Interpret block as column-matrix to mirror the AES specification more closely
    matrix* blk_mat {reinterpret_cast<matrix*>(m_curblk.data())};
    matrix tmp = *blk_mat;

    for (size_t row {0}; row < blk_mat->size(); ++row) {
      for (size_t col {0}; col < (*blk_mat)[row].size(); ++col) {
        // Add shifts[row] to the column index, wrap around at 4
        (*blk_mat)[(col + shifts[row]) % blk_mat->size()][row] = tmp[col][row];
      }
    }
  }

  void AES::mix_columns()
  {
    static constexpr matrix mc {
      {
        {2, 1, 1, 3},
        {3, 2, 1, 1},
        {1, 3, 2, 1},
        {1, 1, 3, 2},
      }
    };

    // Interpret block as column-matrix to mirror the AES specification more closely
    matrix* blk_mat {reinterpret_cast<matrix*>(m_curblk.data())};
    matrix tmp = *blk_mat;

    // Kind of messy matrix multiplication in GF256
    // please refer to https://en.wikipedia.org/wiki/Rijndael_MixColumns
    // and https://www.samiam.org/galois.html for the GF256 math.
    for (size_t col {0}; col < 4; ++col) {
      for (size_t row {0}; row < 4; ++row) {
        (*blk_mat)[col][row] = 0x00;
        for (size_t entry {0}; entry < 4; ++entry) {
          (*blk_mat)[col][row] ^= gf_256_mult(mc[entry][row], tmp[col][entry]);
        }
      }
    }
  }

  // DECRYPTION OPERATIONS
  void AES::inv_sub_bytes()
  {
    for (auto& b : m_curblk) {
      b = inverse_s_box[b];
    }
  }

  void AES::inv_shift_rows()
  {
    // First row is not shifted, second by one bytes to the right, etc.
    // Cyclic shift, so the shifts in shift_rows + inv_shift_rows add up to 0 mod 4
    static constexpr std::array<size_t, 4> shifts {0, 1, 2, 3};

    // Interpret block as column-matrix to mirror the AES specification more closely
    matrix* blk_mat {reinterpret_cast<matrix*>(m_curblk.data())};
    matrix tmp = *blk_mat;

    for (size_t row {1}; row < blk_mat->size(); ++row) {
      for (size_t col {0}; col < (*blk_mat)[row].size(); ++col) {
        // Add shifts[row] to the column index, wrap around at 4
        (*blk_mat)[(col + shifts[row]) % blk_mat->size()][row] = tmp[col][row];
      }
    }
  }

  void AES::inv_mix_columns()
  {
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

    // Interpret block as column-matrix to mirror the AES specification more closely
    matrix* blk_mat {reinterpret_cast<matrix*>(m_curblk.data())};
    matrix tmp = *blk_mat;

    // Kind of messy matrix multiplication in GF256
    // please refer to https://en.wikipedia.org/wiki/Rijndael_MixColumns
    // and https://www.samiam.org/galois.html for the GF256 math.
    for (size_t col {0}; col < 4; ++col) {
      for (size_t row {0}; row < 4; ++row) {
        (*blk_mat)[col][row] = byte{0};
        for (size_t entry {0}; entry < 4; ++entry) {
          (*blk_mat)[col][row] ^= gf_256_mult(inverse_mc[entry][row], tmp[col][entry]);
        }
      }
    }
  }
}