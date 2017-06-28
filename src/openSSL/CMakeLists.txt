cmake_minimum_required(VERSION 2.8)
project(OpenSSL_AES_CSPRNG)
set(CMAKE_C_COMPILER gcc)

add_executable(openSSLTester openssl.c)
find_package(OpenSSL)
target_link_libraries(openSSLTester ${OPENSSL_LIBRARIES})
