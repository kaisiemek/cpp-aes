#include <array>

#include "AES128.h"
#include "SHA256/SHA256.h"

int main()
{
  using std::array, std::cout;
  // From NIST test vector ECBKeySbox128.rsp Count 0
  std::array<uint8_t, 16> input_data {};
  std::array<uint8_t , 16> key_data {
    0x10, 0xa5, 0x88, 0x69,
    0xd7, 0x4b, 0xe5, 0xa3,
    0x74, 0xcf, 0x86, 0x7c,
    0xfb, 0x47, 0x38, 0x59,
  };

  std::string input {"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam placerat velit nec nisi dignissim, non hendrerit ante bibendum. Nulla sit amet pellentesque ex. In et tristique nibh. Nullam consectetur, erat id pellentesque fermentum, lacus tortor dictum dui, eu commodo lorem libero at nunc. Cras nec nisi diam. Aliquam a accumsan sem. Maecenas sed pellentesque ante, at mattis magna. Donec sed lectus sit amet lacus ornare interdum. Phasellus id elementum odio, condimentum pretium ipsum. Cras quis pretium et."};
  std::vector<uint8_t> sha_vec(input.begin(), input.end());
  SHA::SHA256 sha {sha_vec};
  cout << "SHA256 Digest:\n\t";
  cout << sha.digest_str() << '\n';

  AES::Key128 key {std::bit_cast<AES::block>(key_data)};

  AES::AES128 aes {input_data, key};
  aes.encrypt();
  aes.decrypt();

  return 0;
}
