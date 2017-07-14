cmake_minimum_required(VERSION 2.8)
project(libscryptTest)
set(CMAKE_C_COMPILER gcc)

include_directories(scrypt)
link_directories(scrypt)

add_executable(libscryptTest main.c)
target_link_libraries(libscryptTest libscrypt.so)
