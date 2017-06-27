cmake_minimum_required(VERSION 2.8)
project(aesCSPRNG)
set(CMAKE_C_COMPILER gcc)



include_directories(aes)
link_directories(aes)

add_executable(aesCSPRNG main.c)
target_link_libraries(aesCSPRNG aes)

add_executable(aesCompare workingTest.c)
target_link_libraries(aesCompare aes)
find_package(OpenSSL)
target_link_libraries(aesCompare ${OPENSSL_LIBRARIES})