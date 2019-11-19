# this is a cmakefile for the docker, adapt directories to make it work outside it

cmake_minimum_required(VERSION 3.9)
project(pefeats)

set(CMAKE_CXX_STANDARD 14)
add_executable(pefeats pefeats.cpp)
include_directories(/pepac/pelib/include)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
target_link_libraries(pefeats /pepac/pelib/build/src/pelib/libpelib.a)
