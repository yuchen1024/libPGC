# Specify the minimum version for CMake
cmake_minimum_required(VERSION 3.2)

# Project's name 
project(libPGC_openssl)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -O3")

find_package(OPENSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})
  
add_executable(test_pgc test/test_pgc.cpp)

target_link_libraries(test_pgc ${OPENSSL_LIBRARIES})