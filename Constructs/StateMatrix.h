//
// Created by Kai Siemek on 17.12.21.
//

#ifndef AES_CPP_STATEMATRIX_H
#define AES_CPP_STATEMATRIX_H

#include <array>
#include <string>
#include <iostream>

#include "Key128.h"

namespace AES {
  class StateMatrix
  {
  private:
    std::array<std::array<std::byte, 4>, 4> m_data;

  public:
    explicit StateMatrix(std::array<std::byte, 16> block_data);
    void add_key(AES::Key128 key);
    void substitute();
    void shift_rows();
    void mix_columns();

    void inverse_substitute();
    void inverse_shift_rows();
    void inverse_mix_columns();

    [[nodiscard]] std::array<std::byte, 16> get_data() const;

    [[nodiscard]] std::string to_string() const;
  };
}

#endif //AES_CPP_STATEMATRIX_H
