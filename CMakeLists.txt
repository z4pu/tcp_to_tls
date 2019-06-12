# 3.7 to allow builds on debian:stretch-slim Docker image, which has cmake 3.7
cmake_minimum_required (VERSION 3.7)
project (openssl_talk)

# include(CTest)

#################################################################
# option for address sanitizer
#################################################################
option(BUILD_ASAN "Build with address sanitizer" OFF)

#################################################################
# Compiler options
#################################################################
add_compile_options(-std=c++11
    -fPIC -Wall -Wno-unknown-pragmas -Wextra -Wno-variadic-macros
    -Wno-unused-variable -Wno-unused-value -Wno-unused-function
    -Wno-unused-parameter -Wno-uninitialized -Wno-maybe-uninitialized
    -pedantic -Wshadow -Wpointer-arith -Wcast-qual -fpermissive
    -Xlinker --verbose
)
if (BUILD_ASAN)
  add_compile_options(-fsanitize=address -fno-omit-frame-pointer )
endif()

add_subdirectory(src)
