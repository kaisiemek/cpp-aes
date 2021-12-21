//
// Created by Kai Siemek on 17.12.21.
//

#ifndef AES_CPP_STATEMATRIX_H
#define AES_CPP_STATEMATRIX_H

#include <array>
#include <string>
#include <iostream>

#include "../DataTypes.h"

namespace AES {
  class StateMatrix
  {
  private:
    AES::matrix m_data;

  public:
    explicit StateMatrix(block block_data);
    void add_round_key(const round_key &key);
    void sub_bytes();
    void shift_rows();
    void mix_columns();

    void inv_sub_bytes();
    void inv_shift_rows();
    void inv_mix_columns();

    [[nodiscard]] block get_data() const;
    [[nodiscard]] std::string to_string() const;
  };
}

#endif //AES_CPP_STATEMATRIX_H
