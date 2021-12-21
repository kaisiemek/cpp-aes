//
// Created by Kai Siemek on 18.12.21.
//

#ifndef AES_CPP_INPUT_H
#define AES_CPP_INPUT_H

#include "../AES128/Constructs/Key.h"

namespace AES {
  Key generate_key(const std::string& input);
  Key generate_key_cin();
  void interactive_mode();
  std::vector<uint8_t> string_to_data(const std::string& data_str);
}

#endif //AES_CPP_INPUT_H
