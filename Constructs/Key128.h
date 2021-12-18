//
// Created by Kai Siemek on 16.12.21.
//

#ifndef AES_CPP_KEY128_H
#define AES_CPP_KEY128_H

#include <array>
#include <string>
#include <queue>

#include "../Util.h"

namespace AES {
  class Key128
  {
  private:
    block m_data;
  public:
    Key128() = default;
    explicit Key128(block data) : m_data(data) {};
    [[nodiscard]] const block& get_bytes() const;
    [[nodiscard]] Key128 next_key(int round) const;

    [[nodiscard]] std::string to_str() const;

    static std::queue<Key128> get_enc_key_schedule(Key128 key);
  private:
    static word g_function(word data, int round);
  };

}

#endif //AES_CPP_KEY128_H
