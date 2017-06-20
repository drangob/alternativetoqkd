cmake_minimum_required(VERSION 2.8)
project(rdRandThruPut)
set(CMAKE_C_COMPILER gcc)

set (CMAKE_C_FLAGS "-mrdrnd")

add_executable(rdRandThruPut rdRandThruPut.c)
