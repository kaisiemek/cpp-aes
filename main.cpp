#include <array>
#include <bit>

#include "AES128.h"
#include "Constructs/StateMatrix.h"

int main()
{
  using std::array, std::bit_cast, std::cout;
  // From NIST test vector ECBKeySbox128.rsp Count 0
  std::array<uint8_t, 16> input_data {};
  std::array<uint8_t , 16> key_data {
    0x10, 0xa5, 0x88, 0x69,
    0xd7, 0x4b, 0xe5, 0xa3,
    0x74, 0xcf, 0x86, 0x7c,
    0xfb, 0x47, 0x38, 0x59,
  };

  AES::Key128 key {std::bit_cast<AES::block>(key_data)};

  AES::AES128 aes {input_data, key};
  aes.encrypt();
  aes.decrypt();

  return 0;
}
