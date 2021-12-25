cmake_minimum_required(VERSION 3.20)
project(aes_cpp)

set(CMAKE_CXX_STANDARD 20)

add_executable(aes_cpp main.cpp AES/Constants.h "IO Handling/Input.cpp" "IO Handling/Input.h" SHA256/SHA256.cpp SHA256/SHA256.h SHA256/SHA256.cpp SHA256/SHA256.h includes/argparse.hpp AES/AES.cpp AES/AES.h AES/DataTypes.cpp AES/DataTypes.h AES/Constructs/Key.cpp AES/Constructs/Key.h Base64/Base64.cpp Base64/Base64.h AES/RoundOperations.cpp)
