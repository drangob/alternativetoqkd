cmake_minimum_required(VERSION 2.8)
project(RandomCombination)
set(CMAKE_C_COMPILER gcc)

include_directories(aes)
link_directories(aes)

set (CMAKE_C_FLAGS "-mrdrnd")

add_executable(RandomCombination main.c pointerFile.c)
target_link_libraries(RandomCombination opensslAES)
find_package(OpenSSL)
target_link_libraries(RandomCombination ${OPENSSL_LIBRARIES})

add_executable(PtrIncrementer ptrIncrementer.c pointerFile.c)

add_executable(EncryptKeys encryptKeys.c)
target_link_libraries(EncryptKeys opensslAES ${OPENSSL_LIBRARIES})
