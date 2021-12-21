//
// Created by Kai Siemek on 20.12.21.
//

#ifndef AES_CPP_KEY_H
#define AES_CPP_KEY_H

#include <vector>
#include <deque>
#include "../DataTypes.h"
#include "../Constants.h"

namespace AES {
  enum class KeySize {
    AES128, AES192, AES256
  };

  class Key
  {
  private:
    static constexpr int AES128_KEY_WIDTH {128 / 8};
    static constexpr int AES192_KEY_WIDTH {192 / 8};
    static constexpr int AES256_KEY_WIDTH {256 / 8};
    std::vector<byte> m_data;
    std::vector<word> m_expanded_data;

    int m_key_width {};
    int m_round_keys_needed {};
  public:
      explicit Key(std::array<byte, AES128_KEY_WIDTH> data);;
      explicit Key(std::array<byte, AES192_KEY_WIDTH> data);;
      explicit Key(std::array<byte, AES256_KEY_WIDTH> data);;
      // Convenience constructor to create a key from a password.
      Key(std::string_view password, KeySize bitsize);

      std::deque<round_key> generate_key_schedule();
      [[nodiscard]] int get_supported_round_number() const;
  private:
    void key_expansion();
    void set_key_parameters(AES::KeySize keysize);
    // As defined by NIST FIPS-197 Section 5.2
    // Needed for all key sizes
    static word rot_word(word w, int round);
    static word sub_word(word w);
  };
}

#endif //AES_CPP_KEY_H
