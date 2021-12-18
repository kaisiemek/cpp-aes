//
// Created by Kai Siemek on 17.12.21.
//

#include "AES128Encryptor.h"

#include <bit>
#include <iostream>

#include "Constants.h"
#include "Constructs/Key128.h"
#include "Constructs/StateMatrix.h"

namespace AES
{
  AES128Encryptor::AES128Encryptor(const std::array<uint8_t, 16> &data, const AES::Key128 &key)
    : m_state(StateMatrix(std::bit_cast<block>(data))),
      m_key_schedule(Key128::get_enc_key_schedule(key))
  {}

  std::array<uint8_t, 16> AES128Encryptor::encrypt()
  {
    using std::array, std::bit_cast, std::cout;
    cout << "PLAINTEXT:\n\t";
    cout << block_to_string(m_state.get_data()) << '\n';
    cout << "KEY:\n\t" << m_key_schedule.front().to_str() << '\n';

    for (int i{0}; i <= AES128_ENCRYPTION_ROUNDS; ++i)
    {
      // One initial key addition before the actual encryption rounds
      if (i == 0)
      {
        m_state.add_key(m_key_schedule.front());
        m_key_schedule.pop();
        continue;
      }

      m_state.substitute();
      m_state.shift_rows();

      // Do not perform the mix columns step in the last round
      if (i != 10)
      {
        m_state.mix_columns();
      }

      m_state.add_key(m_key_schedule.front());
      m_key_schedule.pop();
    }

    cout << "CYPHERTEXT:\n\t";
    cout << block_to_string(m_state.get_data()) << '\n';

    // Cast back to uint8_t array.
    return bit_cast<array<uint8_t, 16>>(m_state);
  }
}
