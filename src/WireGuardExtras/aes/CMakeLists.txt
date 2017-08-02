cmake_minimum_required(VERSION 2.8)
project(opensslAES)
set(CMAKE_COMPILER gcc)

set (CMAKE_C_FLAGS "-mrdrnd -g")

add_library(opensslAES openssl.c)

find_package(OpenSSL)
target_link_libraries(opensslAES ${OPENSSL_LIBRARIES})

include_directories(../Quantis)
link_directories(../Quantis)

target_link_libraries(opensslAES Quantis)
