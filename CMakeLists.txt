cmake_minimum_required(VERSION 3.20)
project(aes_cpp)

set(CMAKE_CXX_STANDARD 20)

add_executable(aes_cpp main.cpp Constructs/Key128.cpp Constructs/Key128.h Constants.h Constructs/StateMatrix.cpp Constructs/StateMatrix.h Util.cpp Util.h "IO Handling/Input.cpp" "IO Handling/Input.h" SHA256/SHA256.cpp SHA256/SHA256.h SHA256/SHA256.cpp SHA256/SHA256.h includes/argparse.hpp AES128.cpp AES128.h)
