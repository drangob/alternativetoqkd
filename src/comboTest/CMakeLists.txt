cmake_minimum_required(VERSION 2.8)
project(RandomCombination)
set(CMAKE_C_COMPILER gcc)

include_directories(aes)
link_directories(aes)

set (CMAKE_C_FLAGS "-mrdrnd")

add_executable(RandomCombination main.c)
target_link_libraries(RandomCombination aes)
