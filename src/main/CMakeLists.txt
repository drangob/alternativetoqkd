cmake_minimum_required(VERSION 2.8)
project(randomOperation)
set(CMAKE_C_COMPILER gcc)

include_directories(randombitlib)
link_directories(randombitlib)

include_directories(randombitlib/aes)
link_directories(randombitlib/aes)

include_directories(randombitlib/Quantis)
link_directories(randombitlib/Quantis)

include_directories(randombitlib/scrypt)
link_directories(randombitlib/scrypt)

find_package(OpenSSL)

add_executable(RandomGeneration createRandoms.c)
target_link_libraries(RandomGeneration randomWrite opensslAES ${OPENSSL_LIBRARIES} scrypt Quantis)

add_executable(RandomConsumption outputRandoms.c)
target_link_libraries(RandomConsumption randomRead opensslAES ${OPENSSL_LIBRARIES} scrypt Quantis)
