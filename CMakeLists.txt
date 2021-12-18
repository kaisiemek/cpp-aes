cmake_minimum_required(VERSION 3.20)
project(aes_cpp)

set(CMAKE_CXX_STANDARD 20)

add_executable(aes_cpp main.cpp AES128.cpp AES128.h Constructs/Key128.cpp Constructs/Key128.h Constants.h Constructs/StateMatrix.cpp Constructs/StateMatrix.h Util.cpp Util.h)
