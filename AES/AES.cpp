//
// Created by Kai Siemek on 19.12.21.
//

#include "AES.h"

#include <bit>
#include <chrono>
#include <cstring>
#include <utility>
#include <fstream>
#include <iostream>

namespace AES
{
  AES::AES(std::vector<uint8_t> data, Key key)
    : m_data(std::move(data)),
    m_key(std::move(key)),
    m_encryption_rounds(m_key.get_supported_round_number()),
    m_curblk(m_data.data(), 16)
  { }

  // HIGH LEVEL FUNCTIONS
  std::vector<uint8_t> AES::encrypt(bool verbose = false, bool pad = false)
  {
    if (pad)
      pad_data();

    size_t blocks {m_data.size() / sizeof(block)};
    for (int i {0}; i < blocks; ++i) {
      if (verbose)
        std::cout << "=========== BLOCK " << std::dec << i + 1 << "===========\n";
      m_curblk = std::span<byte, 16> {m_data.data() + (i * sizeof(block)), sizeof(block)};
      encrypt_block(verbose);
    }

    return m_data;
  }

  std::vector<uint8_t> AES::decrypt(bool verbose = false)
  {
    size_t blocks {m_data.size() / sizeof(block)};
    for (int i {0}; i < blocks; ++i) {
      if (verbose)
        std::cout << "=========== BLOCK " << std::dec << i + 1 << "===========\n";
      m_curblk = std::span<byte, 16> {m_data.data() + (i * sizeof(block)), sizeof(block)};
      decrypt_block(verbose);
    }

    remove_padding();
    return m_data;
  }

  // BLOCK FUNCTIONS
  void AES::encrypt_block(bool verbose = false)
  {
    using std::cout;
    auto key_schedule{m_key.generate_key_schedule()};

    for (int i{0}; i <= m_encryption_rounds; ++i) {
      if (verbose) {
        cout << "ENCRYPTION ROUND " << std::dec << i << "\n";
        cout << "\tINPUT:\t\t\t\t" << "cur_state.get_data()" << "\n";
      }
      // One initial key addition before the actual encryption rounds
      if (i == 0) {
        add_round_key(key_schedule.front());
        if (verbose)
          cout << "\tAFTER ADDING KEY:\t" << "get_data()" << "\n";
        key_schedule.pop_front();
        continue;
      }

      sub_bytes();
      if (verbose)
        cout << "\tAFTER SUBSTITUTION:\t" << "get_data()" << "\n";
      shift_rows();
      if (verbose)
        cout << "\tAFTER SHIFT ROWS:\t" << "get_data()" << "\n";

      // Do not perform the mix columns step in the last round
      if (i != m_encryption_rounds) {
        mix_columns();
        if (verbose)
          cout << "\tAFTER MIX COLUMNS:\t" << "get_data()" << "\n";
      }

      add_round_key(key_schedule.front());
      if (verbose) {
        cout << "\tUSED KEY:\t\t\t" << key_schedule.front() << "\n";
        cout << "\tAFTER ADDING KEY:\t" << "get_data()" << "\n";
      }
      key_schedule.pop_front();
    }
  }

  void AES::decrypt_block(bool verbose = false)
  {
    using std::cout;
    auto key_schedule {m_key.generate_key_schedule()};

    for (int i {0}; i <= m_encryption_rounds; ++i) {
      if (verbose) {
        cout << "DECRYPTION ROUND " << std::dec << i << "\n";
        cout << "\tINPUT:\t\t\t\t" << "cur_state.get_data()" << "\n";
      }
      add_round_key(key_schedule.back());
      if (verbose) {
        cout << "\tUSED KEY:\t\t\t" << key_schedule.front() << "\n";
        cout << "\tAFTER ADDING KEY:\t" << "get_data()" << "\n";
      }
      key_schedule.pop_back();

      // After the last round do one last key addition but nothing else
      if (i == m_encryption_rounds)
        break;

      // Do not perform the mix columns step in the first round
      if (i != 0) {
        inv_mix_columns();
        if (verbose)
          cout << "\tAFTER MIX COLUMNS:\t" << "get_data()" << "\n";
      }

      inv_shift_rows();
      if (verbose)
        cout << "\tAFTER SHIFT ROWS:\t" << "get_data()" << "\n";
      inv_sub_bytes();
      if (verbose)
        cout << "\tAFTER SUBSTITUTION:\t" << "get_data()" << "\n";
    }
  }

  // PADDING FUNCTION
  // Using 0 padding akin to SHA256 (ISO/IEC 9797-1, padding method 2)
  void AES::pad_data()
  {
    m_data.push_back(0x80);
    size_t num_blocks{(m_data.size() / sizeof(block)) + 1};
    // Increase size, padding the rest with 0 bytes
    m_data.resize(num_blocks * sizeof(block));
  }

  void AES::remove_padding()
  {
    while (m_data.back() == 0x00) {
      m_data.pop_back();
    }
    // Remove the 0x80 byte as well
    m_data.pop_back();
  }

  void AES::encrypt_file(std::ifstream input, std::ofstream output)
  {
    // TODO: try out stream iterator
    // TODO: multithreading
    static constexpr size_t buf_size {sizeof(block) * 1000}; // 1.6 MB
    using std::chrono::high_resolution_clock, std::chrono::duration_cast, std::chrono::milliseconds;

    if (!input)
      throw std::runtime_error{"Could not open file."};

    input.seekg(0, std::ios::end);
    auto end = input.tellg();
    input.seekg(0, std::ios::beg);
    size_t size {static_cast<size_t>(end - input.tellg())};
    if (size == 0) {
      throw std::runtime_error{"File was empty."};
    }

    size_t bytes_to_read {size};

    while (bytes_to_read != 0) {
      m_data.resize(std::min(bytes_to_read, buf_size));

      auto start1 = high_resolution_clock::now();
      if(!input.read(reinterpret_cast<char *>(m_data.data()), static_cast<long>(m_data.size()))) {
        throw std::runtime_error{"Could not read from file."};
      };
      auto stop1 = high_resolution_clock::now();
      std::cout << "Read " << m_data.size() << " bytes in " << duration_cast<milliseconds>(stop1 - start1).count() << "ms\n";

      bytes_to_read -= m_data.size();

      auto start = high_resolution_clock::now();
      auto encrypted_data {encrypt(false, bytes_to_read == 0)};
      auto stop = high_resolution_clock::now();
      std::cout << "\tEncrypted " << m_data.size() << " bytes in " << duration_cast<milliseconds>(stop - start).count() << "ms\n";

      output.write(reinterpret_cast<const char *>(encrypted_data.data()), static_cast<long>(encrypted_data.size()));
    }
  }

  void AES::decrypt_file(std::ifstream ifs, std::ofstream output)
  {
    // TODO: Split in blocks
//    static constexpr size_t buf_size {1024};
    if (!ifs)
      throw std::runtime_error("Could not open file.");

    ifs.seekg(0, std::ios::end);
    auto end = ifs.tellg();

    ifs.seekg(0, std::ios::beg);
    auto size = size_t(end - ifs.tellg());
    if (size == 0) {
      throw std::runtime_error("File was empty.");
    }

    m_data.resize(size);
    if(!ifs.read((char*)m_data.data(), static_cast<long>(m_data.size())))
      throw std::runtime_error("Could not read file.");

    auto res {decrypt(false)};
    output.write(reinterpret_cast<char*>(res.data()), static_cast<long>(res.size()));
  }

}