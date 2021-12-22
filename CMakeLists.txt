cmake_minimum_required(VERSION 3.20)
project(aes_cpp)

set(CMAKE_CXX_STANDARD 20)

add_executable(aes_cpp main.cpp AES128/Constants.h AES128/Constructs/StateMatrix.cpp AES128/Constructs/StateMatrix.h "IO Handling/Input.cpp" "IO Handling/Input.h" SHA256/SHA256.cpp SHA256/SHA256.h SHA256/SHA256.cpp SHA256/SHA256.h includes/argparse.hpp AES128/AES.cpp AES128/AES.h AES128/DataTypes.cpp AES128/DataTypes.h AES128/Constructs/Key.cpp AES128/Constructs/Key.h Base64/Base64.cpp Base64/Base64.h)
