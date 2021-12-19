//
// Created by Kai Siemek on 17.12.21.
//

#include "AES128.h"

#include <bit>
#include <iostream>

#include "Constants.h"
#include "Constructs/Key128.h"
#include "Constructs/StateMatrix.h"

namespace AES
{
  AES128::AES128(const std::array<uint8_t, 16> &data, const AES::Key128 &key)
    : m_state(StateMatrix(std::bit_cast<block>(data))), m_key(key)
  {}

  std::array<uint8_t, 16> AES128::encrypt()
  {
    using std::array, std::bit_cast, std::cout;
    cout << "PLAINTEXT:\n\t";
    cout << block_to_string(m_state.get_data()) << '\n';
    cout << "KEY:\n\t" << m_key.to_str() << '\n';

    auto key_schedule{Key128::get_enc_key_schedule(m_key)};

    for (int i{0}; i <= AES128_ENCRYPTION_ROUNDS; ++i)
    {
      // One initial key addition before the actual encryption rounds
      if (i == 0)
      {
        m_state.add_round_key(key_schedule.front());
        key_schedule.pop();
        continue;
      }

      m_state.sub_bytes();
      m_state.shift_rows();

      // Do not perform the mix columns step in the last round
      if (i != 10)
      {
        m_state.mix_columns();
      }

      m_state.add_round_key(key_schedule.front());
      key_schedule.pop();
    }

    cout << "CIPHERTEXT:\n\t";
    cout << block_to_string(m_state.get_data()) << '\n';

    // Cast back to uint8_t array.
    return bit_cast<array<uint8_t, 16>>(m_state);
  }

  std::array<uint8_t, 16> AES128::decrypt()
  {
    using std::array, std::bit_cast, std::cout;
    cout << "CIPHERTEXT:\n\t";
    cout << block_to_string(m_state.get_data()) << '\n';
    cout << "KEY:\n\t" << m_key.to_str() << '\n';

    auto key_schedule {Key128::get_dec_key_schedule(m_key)};

    for (int i {0}; i <= AES128_ENCRYPTION_ROUNDS; ++i)
    {
      m_state.add_round_key(key_schedule.top());
      key_schedule.pop();

      // After the last round do one last key addition but nothing else
      if (i == AES128_ENCRYPTION_ROUNDS)
      {
        break;
      }

      // Do not perform the mix columns step in the first round
      if (i != 0) {
        m_state.inv_mix_columns();
      }

      m_state.inv_shift_rows();
      m_state.inv_sub_bytes();
    }

    cout << "PLAINTEXT:\n\t";
    cout << block_to_string(m_state.get_data()) << '\n';

    // Cast back to uint8_t array.
    return bit_cast<array<uint8_t, 16>>(m_state);
  }
}
