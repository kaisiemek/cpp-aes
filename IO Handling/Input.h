//
// Created by Kai Siemek on 18.12.21.
//

#ifndef AES_CPP_INPUT_H
#define AES_CPP_INPUT_H

#include <filesystem>
#include <optional>
#include "../AES/Constructs/Key.h"

namespace AES {
  Key generate_key(const std::string& input);
  Key generate_key_cin();
  void interactive_mode();
  void encrypt_file(std::filesystem::path file_path,
                    std::optional<std::filesystem::path> out_path,
                    std::optional<std::string> password,
                    bool encrypt,
                    bool decrypt);
  std::vector<uint8_t> string_to_data(const std::string& data_str);
}

#endif //AES_CPP_INPUT_H
