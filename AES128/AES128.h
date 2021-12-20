//
// Created by Kai Siemek on 19.12.21.
//

#ifndef AES_CPP_AES128_H
#define AES_CPP_AES128_H

#include "DataTypes.h"
#include "Constructs/StateMatrix.h"
#include "Constructs/Key128.h"

namespace AES
{
  class AES128
  {
  private:
    static constexpr int BLOCK_SIZE {16};
    static constexpr int ENCRYPTION_ROUNDS {10};

    Key128 m_key;
    std::vector<byte> m_data;
  public:
    AES128(std::vector<byte> data, const Key128 &key);
    std::vector<byte> encrypt();
    std::vector<byte> decrypt();
  private:
    void pad_data();
    void remove_padding();
    block encrypt_block(block blk);
    block decrypt_block(block blk);
  };
}

#endif //AES_CPP_AES128_H
