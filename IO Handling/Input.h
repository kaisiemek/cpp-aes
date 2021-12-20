//
// Created by Kai Siemek on 18.12.21.
//

#ifndef AES_CPP_INPUT_H
#define AES_CPP_INPUT_H

#include "../AES128/Constructs/Key128.h"

namespace AES {
  Key128 generate_key(const std::string& input);
  AES::Key128 generate_key_cin();
  void interactive_mode();
  std::vector<uint8_t> string_to_data(const std::string& data_str);
}

#endif //AES_CPP_INPUT_H
