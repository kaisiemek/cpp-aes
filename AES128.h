//
// Created by Kai Siemek on 19.12.21.
//

#ifndef AES_CPP_AES128_H
#define AES_CPP_AES128_H

#include "Constructs/StateMatrix.h"
#include "Constructs/Key128.h"

namespace AES
{

  class AES128
  {
    using block_t = std::array<uint8_t, 16>;
  private:
    static constexpr uint8_t BLOCK_SIZE {16};
    static constexpr uint8_t ENCRYPTION_ROUNDS {10};

    Key128 m_key;
    std::vector<uint8_t> m_data;
  public:
    AES128(std::vector<uint8_t> data, const Key128 &key);
    std::vector<uint8_t> encrypt();
    std::vector<uint8_t> decrypt();

//    std::array<uint8_t, 16> decrypt();

  private:
    void pad_data();
    void remove_padding();
    block_t encrypt_block(block_t blk);
    block_t decrypt_block(block_t blk);
  };
}

#endif //AES_CPP_AES128_H
