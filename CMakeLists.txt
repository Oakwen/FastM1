cmake_minimum_required(VERSION 3.0.0)
project(fastm1 VERSION 0.1.0)
set(CMAKE_SYSTEM_NAME Windows)

project(fastm1 C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_COMPILER gcc)
set(CMAKE_C_FLAGS -m32)

include_directories(include)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/lib)

aux_source_directory(src DIR_SRCS)

add_library(nfcutils STATIC src/nfc-utils.c)
set_target_properties(nfcutils PROPERTIES COMPILE_FLAGS"-m32" LINK_FLAGS"-m32")

add_library(mifare STATIC src/mifare.c)

add_executable(fastm1  ${CMAKE_CURRENT_SOURCE_DIR}/src/fastm1.c)
set_target_properties(fastm1 PROPERTIES COMPILE_FLAGS"-m32" LINK_FLAGS"-m32")
target_link_libraries(fastm1 nfcutils mifare nfc)

add_executable(test_libnfc ${CMAKE_CURRENT_SOURCE_DIR}/src/test_libnfc.c)
target_link_libraries(test_libnfc nfcutils mifare nfc)
