//
// Created by Kai Siemek on 17.12.21.
//

#ifndef AES_CPP_AES128_H
#define AES_CPP_AES128_H

#include "Constructs/StateMatrix.h"
#include "Constructs/Key128.h"

namespace AES {
  class AES128
  {
  private:
    StateMatrix m_state;
    Key128 m_key;
  public:
    // TODO: make vector of variable length
    AES128(const std::array<uint8_t, 16>& data, const Key128& key);
    std::array<uint8_t, 16> encrypt();
    std::array<uint8_t, 16> decrypt();
  };
}

#endif //AES_CPP_AES128_H
