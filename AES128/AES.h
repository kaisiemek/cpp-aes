//
// Created by Kai Siemek on 19.12.21.
//

#ifndef AES_CPP_AES_H
#define AES_CPP_AES_H

#include "DataTypes.h"
#include "Constructs/StateMatrix.h"
#include "Constructs/Key.h"

namespace AES
{
  class AES
  {
  private:
    static constexpr int ENCRYPTION_ROUNDS {10};

    Key m_key;
    std::vector<byte> m_data;
    int m_encryption_rounds {};
  public:
    AES(std::vector<byte> data, Key key);
    std::vector<uint8_t> encrypt(bool verbose);
    std::vector<uint8_t> decrypt(bool verbose);
  private:
    void pad_data();
    void remove_padding();
    block encrypt_block(block blk, bool verbose);
    block decrypt_block(block blk, bool verbose);
  };
}

#endif //AES_CPP_AES_H
