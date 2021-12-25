//
// Created by Kai Siemek on 18.12.21.
//

#include "Input.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <iomanip>
#include "../SHA256/SHA256.h"
#include "../AES/AES.h"

namespace AES
{

  Key generate_key(const std::string &input)
  {
    SHA::SHA256 sha{std::vector<SHA::byte>{input.begin(), input.end()}};
    auto sha_digest{sha.create_digest()};

    block key_data;
    // Copy half the SHA digest (128 bit) into the key data array
    // This is not a secure way of creating AES keys!
    std::memcpy(key_data.begin(), sha_digest.begin(), sizeof(block));

    Key key{key_data};
    std::cout << "Generated key\n\t" << key_data << "\nfrom data\n\t" << input << "\n";
    return key;
  }

  Key generate_key_cin()
  {
    using namespace std;
    string pw1, pw2;
    cout << "Please enter a passphrase:\n> ";
    cin >> pw1;

    cout << "Please confirm the passphrase:\n> ";
    cin >> pw2;

    if (pw1 != pw2)
    {
      cerr << "The passwords did not match up.\n";
      std::exit(2);
    }

    return generate_key(pw1);
  }

  void interactive_mode()
  {
    using namespace std;
    cout << "Welcome to aes-cpp, please enter data to encrypt/decrypt:\n> ";
    string user_data;
    getline(cin, user_data);

    auto key{generate_key_cin()};

    cout << "Do you want to encrypt or decrypt the provided data? (e/d)\n> ";
    string response;
    cin >> response;

    if (response == "e")
    {
      vector<uint8_t> data{user_data.begin(), user_data.end()};
      AES aes{data, key};
      auto res = aes.encrypt(false, false);
      for (auto x: res)
      {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << +x;
      }
      std::cout << std::endl;
    } else if (response == "d")
    {
      vector<uint8_t> data{string_to_data(user_data)};
      AES aes{data, key};
      auto res = aes.decrypt(false);
      string res_str{res.begin(), res.end()};
      std::cout << res_str << std::endl;
    } else
    {
      cerr << "Invalid option, please choose 'e' or 'd' next time\n";
      std::exit(2);
    }
  }

  std::vector<uint8_t> string_to_data(const std::string &data_str)
  {
    std::vector<uint8_t> data;
    for (size_t i{0}; i < data_str.length(); i += 2)
    {
      std::string byte_str{data_str.substr(i, 2)};
      data.emplace_back(stol(byte_str, nullptr, 16));
    }
    return data;
  }
}
  void AES::encrypt_file(std::filesystem::path file_path, std::optional<std::filesystem::path> out_path,
                         std::optional<std::string> password, bool encrypt, bool decrypt)
  {
  using namespace AES;
    if (!std::filesystem::is_regular_file(file_path)) {
      std::cerr << "'" << file_path << "' is not a regular file.\n";
      std::exit(2);
    }

    std::filesystem::path ofp;
    if (!out_path.has_value()) {
      std::cout << "No outfile path is given, please enter a path:\n> ";
//      std::getline(std::cin, ofp);
      std::cin >> ofp;
      std::cout << '\n';
      std::filesystem::create_directories(ofp.parent_path());
    } else {
      ofp = out_path.value();
    }

    std::string pw1, pw2;
    if (!password.has_value()) {
      std::cout << "No password was given, please enter a password:\n> ";
      std::cin >> pw1;
      std::cout << "Repeat the password:\n> ";
      std::cin >> pw2;

      if (pw1 != pw2) {
        std::cerr << "The passwords did not match up\n";
        std::exit(2);
      }
    } else {
      pw1 = password.value();
    }

    if (!encrypt && !decrypt) {
      std::string answer;
      std::cout << "No mode was specified, do you want to encrypt or decrypt (e/d)?\n> ";
      std::cin >> answer;

      if (answer == "e") {
        encrypt = true;
        decrypt = false;
      } else if (answer == "d") {
        encrypt = false;
        decrypt = true;
      } else {
        std::cerr << "'" << answer << "' was not a valid option\n";
        std::exit(2);
      }
    }

    if (encrypt) {
      Key key {pw1, KeySize::AES256};
      AES aes {std::vector<byte>{}, key};
      aes.encrypt_file({file_path, std::ios::binary}, {ofp, std::ios::binary});
    } else {
      Key key {pw1, KeySize::AES256};
      AES aes {std::vector<byte>{}, key};
      aes.decrypt_file({file_path, std::ios::binary | std::ios::ate}, {ofp});
    }
  }