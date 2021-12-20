//
// Created by Kai Siemek on 19.12.21.
//

#include "AES128.h"

#include <bit>
#include <cstring>
#include "Constants.h"

namespace AES
{
  AES128::AES128(std::vector<uint8_t> data, const Key128 &key)
    : m_data(std::move(data)), m_key(key)
  { }

  std::vector<uint8_t> AES128::encrypt()
  {
    pad_data();
    block cur_block {};
    size_t blocks {m_data.size() / sizeof(block)};
    for (int i {0}; i < blocks; ++i) {
      std::memcpy(cur_block.data(), m_data.data() + (i * sizeof(block)), sizeof(block));
      cur_block = encrypt_block(cur_block);
      std::memcpy(m_data.data() + (i * sizeof(block)), cur_block.data(), sizeof(block));
    }

    return m_data;
  }

  std::vector<uint8_t> AES128::decrypt()
  {
    block cur_block {};
    size_t blocks {m_data.size() / sizeof(block)};
    for (int i {0}; i < blocks; ++i) {
      std::memcpy(cur_block.data(), m_data.data() + (i * sizeof(block)), sizeof(block));
      cur_block = decrypt_block(cur_block);
      std::memcpy(m_data.data() + (i * sizeof(block)), cur_block.data(), sizeof(block));
    }

    remove_padding();
    return m_data;
  }

  // Using 0 padding akin to SHA256 (ISO/IEC 9797-1, padding method 2)
  void AES128::pad_data()
  {
    m_data.push_back(0x80);
    size_t num_blocks{(m_data.size() / BLOCK_SIZE) + 1};
    // Increase size, padding the rest with 0 bytes
    m_data.resize(num_blocks * BLOCK_SIZE);
  }

  block AES128::encrypt_block(block blk)
  {
    using std::array, std::bit_cast, std::cout;
    StateMatrix cur_state {blk};
    auto key_schedule{Key128::generate_key_schedule(m_key)};

    for (int i{0}; i <= ENCRYPTION_ROUNDS; ++i) {
//      cout << "ENCRYPTION ROUND " << std::dec << i << "\n";
//      cout << "\tINPUT:\t\t\t\t" << cur_state.get_data() << "\n";
      // One initial key addition before the actual encryption rounds
      if (i == 0) {
        cur_state.add_round_key(key_schedule.front());
//        cout << "\tAFTER ADDING KEY:\t" << cur_state.get_data() << "\n";
        key_schedule.pop_front();
        continue;
      }

      cur_state.sub_bytes();
//      cout << "\tAFTER SUBSTITUTION:\t" << cur_state.get_data() << "\n";
      cur_state.shift_rows();
//      cout << "\tAFTER SHIFT ROWS:\t" << cur_state.get_data() << "\n";

      // Do not perform the mix columns step in the last round
      if (i != 10)
      {
        cur_state.mix_columns();
//        cout << "\tAFTER MIX COLUMNS:\t" << cur_state.get_data() << "\n";
      }

      cur_state.add_round_key(key_schedule.front());
//      cout << "\tAFTER ADDING KEY:\t" << cur_state.get_data() << "\n";
      key_schedule.pop_front();
    }

    // Cast back to uint8_t array.
    return cur_state.get_data();
  }

  block AES128::decrypt_block(block blk)
  {
    using std::array, std::bit_cast, std::cout;
    StateMatrix cur_state {blk};
    auto key_schedule {Key128::generate_key_schedule(m_key)};

    for (int i {0}; i <= ENCRYPTION_ROUNDS; ++i) {
//      cout << "ENCRYPTION ROUND " << std::dec << i << "\n";
//      cout << "\tINPUT:\t\t\t\t" << cur_state.get_data() << "\n";
      cur_state.add_round_key(key_schedule.back());
//      cout << "\tAFTER ADDING KEY:\t" << cur_state.get_data() << "\n";
      key_schedule.pop_back();
      // After the last round do one last key addition but nothing else
      if (i == ENCRYPTION_ROUNDS) {
        break;
      }

      // Do not perform the mix columns step in the first round
      if (i != 0) {
        cur_state.inv_mix_columns();
//        cout << "\tAFTER MIX COLUMNS:\t" << cur_state.get_data() << "\n";
      }
      cur_state.inv_shift_rows();
//      cout << "\tAFTER SHIFT ROWS:\t" << cur_state.get_data() << "\n";
      cur_state.inv_sub_bytes();
//      cout << "\tAFTER SUBSTITUTION:\t" << cur_state.get_data() << "\n";
    }

    // Cast back to uint8_t array.
    return bit_cast<block>(cur_state);
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