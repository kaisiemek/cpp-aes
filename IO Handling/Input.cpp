//
// Created by Kai Siemek on 18.12.21.
//

#include "Input.h"
#include <iostream>
#include <cstring>
#include <iomanip>
#include "../SHA256/SHA256.h"
#include "../AES128/AES.h"
#include "../AES128/Constructs/Key.h"
#include "../AES128/DataTypes.h"

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
      auto res = aes.encrypt(false);
      for (auto x: res)
      {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << +x;
      }
      std::cout << std::endl;
    } else if (response == "d")
    {
      vector<uint8_t> data{string_to_data(user_data)};
      AES aes {data, key};
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