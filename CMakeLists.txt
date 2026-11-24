cmake_minimum_required(VERSION 3.16)
project(ddp_claw_integrity VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(ddp_integrity src/integrity.cpp)
target_include_directories(ddp_integrity PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(ddp_integrity PUBLIC OpenSSL::Crypto)
target_compile_options(ddp_integrity PRIVATE -Wall -Wextra -Wpedantic)

add_executable(ddp src/main.cpp)
target_link_libraries(ddp PRIVATE ddp_integrity)

include(CTest)
if(BUILD_TESTING)
  add_executable(ddp_integrity_tests tests/integrity_tests.cpp)
  target_link_libraries(ddp_integrity_tests PRIVATE ddp_integrity)
  add_test(NAME ddp_integrity_tests COMMAND ddp_integrity_tests)
endif()
