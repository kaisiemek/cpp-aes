//
// Created by Kai Siemek on 16.12.21.
//

#ifndef AES_CPP_KEY128_H
#define AES_CPP_KEY128_H

#include <array>
#include <string>
#include <queue>
#include <stack>

#include "../DataTypes.h"

namespace AES {
  class Key128
  {
  private:
    static constexpr int SCHEDULE_KEY_NUM {11};
    block m_data;
  public:
    Key128() = default;
    explicit Key128(block data) : m_data(data) {};
    [[nodiscard]] const block& get_bytes() const;
    [[nodiscard]] std::string to_str() const;

    static std::deque<Key128> generate_key_schedule(Key128 initial_key);
  private:
    [[nodiscard]] Key128 next_key(int round) const;
    static word g_function(word data, int round);
  };

}

#endif //AES_CPP_KEY128_H
