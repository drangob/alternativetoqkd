cmake_minimum_required(VERSION 2.8)
project(RandomCombination)
set(CMAKE_C_COMPILER gcc)

include_directories(aes)
link_directories(aes)

include_directories(scrypt)
link_directories(scrypt)

include_directories(Quantis)
link_directories(Quantis)

find_package(OpenSSL)

set (CMAKE_C_FLAGS "-mrdrnd -g")

add_executable(RandomGeneration bitGeneration.c pointerFile.c encryptKeys.c)
target_link_libraries(RandomGeneration opensslAES ${OPENSSL_LIBRARIES} scrypt Quantis)

add_executable(RandomConsumption ptrIncrementer.c pointerFile.c encryptKeys.c)
target_link_libraries(RandomConsumption opensslAES ${OPENSSL_LIBRARIES} scrypt Quantis)

add_executable(tester tester.c pointerFile.c)
target_link_libraries(tester opensslAES ${OPENSSL_LIBRARIES} scrypt Quantis)
