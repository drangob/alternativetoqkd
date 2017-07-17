cmake_minimum_required(VERSION 2.8)
project(TestQuantis)
set(CMAKE_C_COMPILER gcc)

include_directories(Quantis)
link_directories(Quantis)

add_executable(TestQuantis quantisTest.c)
target_link_libraries(TestQuantis Quantis)
