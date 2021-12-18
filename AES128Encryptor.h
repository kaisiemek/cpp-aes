//
// Created by Kai Siemek on 17.12.21.
//

#ifndef AES_CPP_AES128ENCRYPTOR_H
#define AES_CPP_AES128ENCRYPTOR_H

#include "Constructs/StateMatrix.h"
#include "Constructs/Key128.h"

namespace AES {
  class AES128Encryptor
  {
  private:
    StateMatrix m_state;
    std::queue<Key128> m_key_schedule;
  public:
    // TODO: make vector of variable length
    AES128Encryptor(const std::array<uint8_t, 16>& data, const Key128& key);
    std::array<uint8_t, 16> encrypt();
  };
}

#endif //AES_CPP_AES128ENCRYPTOR_H
