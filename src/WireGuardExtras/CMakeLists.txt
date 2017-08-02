cmake_minimum_required(VERSION 2.8)
project(RandomProvider)
set(CMAKE_C_COMPILER gcc)

include_directories(aes)
link_directories(aes)

include_directories(scrypt)
link_directories(scrypt)

include_directories(Quantis)
link_directories(Quantis)

find_package(OpenSSL)

set (CMAKE_C_FLAGS "-mrdrnd -g")

add_executable(RandomProvider ptrIncrementer.c pointerFile.c encryptKeys.c)
target_link_libraries(RandomProvider opensslAES ${OPENSSL_LIBRARIES} scrypt Quantis)
