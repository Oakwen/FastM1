cmake_minimum_required(VERSION 3.0.0)
project(fastm1 VERSION 0.1.0)

project(fastm1 C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_COMPILER gcc)
set(CMAKE_C_FLAGS -m32)

include_directories(include)

# link_directories(${CMAKE_CURRENT_SOURCE_DIR})
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/lib)
link_directories(/C/WINDOWS/SysWOW64)

AUX_SOURCE_DIRECTORY(src DIR_SRCS)

ADD_LIBRARY(nfcutils STATIC include/nfc-utils.c)

add_executable(fastm1  ${CMAKE_CURRENT_SOURCE_DIR}/src/fastm1.c)
TARGET_LINK_LIBRARIES(fastm1 nfcutils nfc)
