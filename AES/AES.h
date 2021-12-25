//
// Created by Kai Siemek on 19.12.21.
//

#ifndef AES_CPP_AES_H
#define AES_CPP_AES_H

#include "DataTypes.h"
#include <vector>
#include <filesystem>
#include <span>
#include "Constructs/Key.h"

namespace AES
{
  class AES
  {
  private:
    Key m_key;
    std::vector<byte> m_data;
    std::span<byte, 16> m_curblk;
    int m_encryption_rounds {};
  public:
    AES(std::vector<byte> data, Key key);
    std::vector<uint8_t> encrypt(bool verbose, bool pad);
    std::vector<uint8_t> decrypt(bool verbose);
    void encrypt_file(std::ifstream input, std::ofstream output);
    void decrypt_file(std::ifstream input, std::ofstream output);
  private:
    void pad_data();
    void remove_padding();
    void encrypt_block(bool verbose);
    void decrypt_block(bool verbose);

  // Round operations
  private:
    void add_round_key(std::span<const byte, 16> round_key);

    void sub_bytes();
    void shift_rows();
    void mix_columns();

    void inv_sub_bytes();
    void inv_shift_rows();
    void inv_mix_columns();
  };
}

#endif //AES_CPP_AES_H
