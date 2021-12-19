//
// Created by Kai Siemek on 19.12.21.
//

#include "AES128.h"

#include <bit>
#include <cstring>

namespace AES
{
  AES128::AES128(std::vector<uint8_t> data, const Key128 &key)
    : m_data(std::move(data)), m_key(key)
  { }

// Using 0 padding akin to SHA256 (ISO/IEC 9797-1, padding method 2)
  void AES128::pad_data()
  {
    m_data.push_back(0x80);
    size_t num_blocks{(m_data.size() / BLOCK_SIZE) + 1};
    // Increase size, padding the rest with 0 bytes
    m_data.resize(num_blocks * BLOCK_SIZE);
  }

  AES128::block_t AES128::encrypt_block(block_t blk)
  {
    using std::array, std::bit_cast, std::cout;
    StateMatrix cur_state {bit_cast<array<std::byte, 16>>(blk)};
    auto key_schedule{Key128::get_enc_key_schedule(m_key)};

    for (int i{0}; i <= ENCRYPTION_ROUNDS; ++i)
    {
      // One initial key addition before the actual encryption rounds
      if (i == 0)
      {
        cur_state.add_round_key(key_schedule.front());
        key_schedule.pop();
        continue;
      }

      cur_state.sub_bytes();
      cur_state.shift_rows();

      // Do not perform the mix columns step in the last round
      if (i != 10)
      {
        cur_state.mix_columns();
      }

      cur_state.add_round_key(key_schedule.front());
      key_schedule.pop();
    }

    // Cast back to uint8_t array.
    return bit_cast<array<uint8_t, 16>>(cur_state);
  }

  std::vector<uint8_t> AES128::encrypt()
  {
    pad_data();
    block_t cur_block {};
    size_t blocks {m_data.size() / sizeof(block_t)};
    for (int i {0}; i < blocks; ++i) {
      std::memcpy(cur_block.data(), m_data.data() + (i * sizeof(block_t)), sizeof(block_t));
      cur_block = encrypt_block(cur_block);
      std::memcpy(m_data.data() + (i * sizeof(block_t)), cur_block.data(), sizeof(block_t));
    }

    return m_data;
  }

  std::vector<uint8_t> AES128::decrypt()
  {
    block_t cur_block {};
    size_t blocks {m_data.size() / sizeof(block_t)};
    for (int i {0}; i < blocks; ++i) {
      std::memcpy(cur_block.data(), m_data.data() + (i * sizeof(block_t)), sizeof(block_t));
      cur_block = decrypt_block(cur_block);
      std::memcpy(m_data.data() + (i * sizeof(block_t)), cur_block.data(), sizeof(block_t));
    }

    remove_padding();
    return m_data;
  }

  AES128::block_t AES128::decrypt_block(AES128::block_t blk)
  {
    using std::array, std::bit_cast, std::cout;
    StateMatrix cur_state {bit_cast<array<std::byte, 16>>(blk)};
    auto key_schedule {Key128::get_dec_key_schedule(m_key)};

    for (int i {0}; i <= ENCRYPTION_ROUNDS; ++i)
    {
      cur_state.add_round_key(key_schedule.top());
      key_schedule.pop();

      // After the last round do one last key addition but nothing else
      if (i == ENCRYPTION_ROUNDS)
      {
        break;
      }

      // Do not perform the mix columns step in the first round
      if (i != 0) {
        cur_state.inv_mix_columns();
      }

      cur_state.inv_shift_rows();
      cur_state.inv_sub_bytes();
    }

    // Cast back to uint8_t array.
    return bit_cast<block_t>(cur_state);
  }

  void AES128::remove_padding()
  {
    while (m_data.back() == 0x00) {
      m_data.pop_back();
    }
    // Remove the 0x80 byte as well
    m_data.pop_back();
  }
}