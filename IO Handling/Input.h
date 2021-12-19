//
// Created by Kai Siemek on 18.12.21.
//

#ifndef AES_CPP_INPUT_H
#define AES_CPP_INPUT_H

#include "../Constructs/Key128.h"

namespace AES {
  Key128 construct_key(const std::string& input);
}

#endif //AES_CPP_INPUT_H
