cmake_minimum_required(VERSION 2.8)
project(RandomProvider)
set(CMAKE_C_COMPILER gcc)

include_directories(../main/randombitlib/)
link_directories(../main/randombitlib/)

include_directories(../main/randombitlib/aes)
link_directories(../main/randombitlib/aes)

include_directories(../main/randombitlib/scrypt)
link_directories(../main/randombitlib/scrypt)

include_directories(../main/randombitlib/Quantis)
link_directories(../main/randombitlib/Quantis)

find_package(OpenSSL)

set (CMAKE_C_FLAGS "-mrdrnd -g")

add_executable(RandomProvider randomProvider.c)
target_link_libraries(RandomProvider randomRead opensslAES ${OPENSSL_LIBRARIES} scrypt Quantis)
