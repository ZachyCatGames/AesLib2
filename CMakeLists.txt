# CMakeList.txt : CMake project for AesLib, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Set standard.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED yes)

# Add source files to lib.
add_library(AesLib STATIC "include/Aes128.h" "source/AesCbc128.cpp" "include/AesCbc128.h" "include/AesCommon128.h" "source/AesCtr128.cpp" "include/AesCtr128.h" "source/AesEcb128.cpp" "include/AesEcb128.h" "include/AesLookupTables.h" "source/AesXts128.cpp" "include/AesXts128.h")
target_include_directories(AesLib PUBLIC include)
