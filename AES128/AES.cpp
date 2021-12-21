//
// Created by Kai Siemek on 19.12.21.
//

#include "AES.h"

#include <bit>
#include <cstring>
#include <utility>

namespace AES
{
  AES::AES(std::vector<uint8_t> data, Key key)
    : m_data(std::move(data)), m_key(std::move(key)), m_encryption_rounds(m_key.get_supported_round_number())
  { }

  std::vector<uint8_t> AES::encrypt(bool verbose = false)
  {
    pad_data();
    block cur_block {};
    size_t blocks {m_data.size() / sizeof(block)};
    for (int i {0}; i < blocks; ++i) {
      std::memcpy(cur_block.data(), m_data.data() + (i * sizeof(block)), sizeof(block));
      if (verbose)
        std::cout << "=========== BLOCK " << std::dec << i + 1 << "===========\n";
      cur_block = encrypt_block(cur_block, verbose);
      std::memcpy(m_data.data() + (i * sizeof(block)), cur_block.data(), sizeof(block));
    }

    return m_data;
  }

  std::vector<uint8_t> AES::decrypt(bool verbose = false)
  {
    block cur_block {};
    size_t blocks {m_data.size() / sizeof(block)};
    for (int i {0}; i < blocks; ++i) {
      std::memcpy(cur_block.data(), m_data.data() + (i * sizeof(block)), sizeof(block));
      if (verbose)
        std::cout << "=========== BLOCK " << std::dec << i + 1 << "===========\n";
      cur_block = decrypt_block(cur_block, verbose);
      std::memcpy(m_data.data() + (i * sizeof(block)), cur_block.data(), sizeof(block));
    }

    remove_padding();
    return m_data;
  }

  // Using 0 padding akin to SHA256 (ISO/IEC 9797-1, padding method 2)
  void AES::pad_data()
  {
    m_data.push_back(0x80);
    size_t num_blocks{(m_data.size() / sizeof(block)) + 1};
    // Increase size, padding the rest with 0 bytes
    m_data.resize(num_blocks * sizeof(block));
  }

  block AES::encrypt_block(block blk, bool verbose = false)
  {
    using std::array, std::bit_cast, std::cout;
    StateMatrix cur_state {blk};
    auto key_schedule{m_key.generate_key_schedule()};

    for (int i{0}; i <= m_encryption_rounds; ++i) {
      if (verbose) {
        cout << "ENCRYPTION ROUND " << std::dec << i << "\n";
        cout << "\tINPUT:\t\t\t\t" << cur_state.get_data() << "\n";
      }
      // One initial key addition before the actual encryption rounds
      if (i == 0) {
        cur_state.add_round_key(key_schedule.front());
        if (verbose)
          cout << "\tAFTER ADDING KEY:\t" << cur_state.get_data() << "\n";
        key_schedule.pop_front();
        continue;
      }

      cur_state.sub_bytes();
      if (verbose)
        cout << "\tAFTER SUBSTITUTION:\t" << cur_state.get_data() << "\n";
      cur_state.shift_rows();
      if (verbose)
        cout << "\tAFTER SHIFT ROWS:\t" << cur_state.get_data() << "\n";

      // Do not perform the mix columns step in the last round
      if (i != m_encryption_rounds)
      {
        cur_state.mix_columns();
        if (verbose)
          cout << "\tAFTER MIX COLUMNS:\t" << cur_state.get_data() << "\n";
      }

      cur_state.add_round_key(key_schedule.front());
      if (verbose) {
        cout << "\tUSED KEY:\t\t\t" << key_schedule.front() << "\n";
        cout << "\tAFTER ADDING KEY:\t" << cur_state.get_data() << "\n";
      }
      key_schedule.pop_front();
    }

    // Cast back to uint8_t array.
    return cur_state.get_data();
  }

  block AES::decrypt_block(block blk, bool verbose = false)
  {
    using std::array, std::bit_cast, std::cout;
    StateMatrix cur_state {blk};
    auto key_schedule {m_key.generate_key_schedule()};

    for (int i {0}; i <= m_encryption_rounds; ++i) {
      if (verbose) {
        cout << "DECRYPTION ROUND " << std::dec << i << "\n";
        cout << "\tINPUT:\t\t\t\t" << cur_state.get_data() << "\n";
      }
      cur_state.add_round_key(key_schedule.back());
      if (verbose) {
        cout << "\tUSED KEY:\t\t\t" << key_schedule.front() << "\n";
        cout << "\tAFTER ADDING KEY:\t" << cur_state.get_data() << "\n";
      }
      key_schedule.pop_back();

      // After the last round do one last key addition but nothing else
      if (i == m_encryption_rounds)
        break;

      // Do not perform the mix columns step in the first round
      if (i != 0) {
        cur_state.inv_mix_columns();
        if (verbose)
          cout << "\tAFTER MIX COLUMNS:\t" << cur_state.get_data() << "\n";
      }

      cur_state.inv_shift_rows();
      if (verbose)
        cout << "\tAFTER SHIFT ROWS:\t" << cur_state.get_data() << "\n";
      cur_state.inv_sub_bytes();
      if (verbose)
        cout << "\tAFTER SUBSTITUTION:\t" << cur_state.get_data() << "\n";
    }

    // Cast back to uint8_t array.
    return bit_cast<block>(cur_state);
  }

  void AES::remove_padding()
  {
    while (m_data.back() == 0x00) {
      m_data.pop_back();
    }
    // Remove the 0x80 byte as well
    m_data.pop_back();
  }
}