cmake_minimum_required(VERSION 2.8)
project(opensslAES)
set(CMAKE_COMPILER gcc)

add_library(opensslAES openssl.c)

find_package(OpenSSL)
target_link_libraries(opensslAES ${OPENSSL_LIBRARIES})