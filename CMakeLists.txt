# CMakeList.txt : CMake project for AesLib, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)
project(AesLib)

# Set standard.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED yes)

# Add include dir
include_directories(include)

add_compile_options(-mtune=native -march=native)

# Add source files to lib.
add_library(AesLib STATIC
    "include/AesLib/detail/AesByteSwap.h"
#    "include/AesLib/detail/AesDecryptImpl128.cpu-amd64.h" "source/detail/AesDecryptImpl128.cpu-amd64.cpp"
    "include/AesLib/detail/AesDecryptImpl128.cpu-generic.h" "source/detail/AesDecryptImpl128.cpu-generic.cpp"
    "include/AesLib/detail/AesDecryptImpl128.h"
#    "include/AesLib/detail/AesEncryptImpl128.cpu-amd64.h" "source/detail/AesEncryptImpl128.cpu-amd64.cpp"
    "include/AesLib/detail/AesEncryptImpl128.cpu-generic.h" "source/detail/AesEncryptImpl128.cpu-generic.cpp"
    "include/AesLib/detail/AesEncryptImpl128.h"
    "include/AesLib/detail/AesGFMul.h" "source/detail/AesGFMul.cpp"
#    "include/AesLib/detail/AesXorBlock128.h" "source/detail/AesXorBlock128.cpu-amd64.cpp"
    "include/AesLib/detail/AesXorBlock128.h" "source/detail/AesXorBlock128.cpu-generic.cpp"
    "include/AesLib/detail/AesSimdKeyExpansion.cpu-amd64.h" "source/detail/AesSimdKeyExpansion.cpu-amd64.cpp"
    "include/AesLib/detail/AesXtsTweakHandler.h" "source/detail/AesXtsTweakHandler.cpp"

    "include/AesLib/Aes128.h"
    "include/AesLib/AesCommon.h"
    "include/AesLib/AesLookupTables.h"
    "include/AesLib/AesEcbDecryptor128.h" "source/AesEcbDecryptor128.cpp"
    "include/AesLib/AesEcbEncryptor128.h" "source/AesEcbEncryptor128.cpp"
    "include/AesLib/AesCbcDecryptor128.h" "source/AesCbcDecryptor128.cpp"
    "include/AesLib/AesCbcEncryptor128.h" "source/AesCbcEncryptor128.cpp"
    "include/AesLib/AesXtsDecryptor128.h" "source/AesXtsDecryptor128.cpp"
    "include/AesLib/AesXtsEncryptor128.h" "source/AesXtsEncryptor128.cpp"
    "include/AesLib/AesCtr128.h" "source/AesCtr128.cpp" 
)
target_include_directories(AesLib PUBLIC include)

# Create test exe.
add_executable(AesLibTest
    "test_program/test_Main.cpp"
    "test_program/test_TestData.h"
    "test_program/test_EcbEncData.h"
    "test_program/test_AesEcbTest.h" "test_program/test_AesEcbTest.cpp"
    "test_program/test_AesCbcTest.h" "test_program/test_AesCbcTest.cpp"
)
target_link_libraries(AesLibTest PUBLIC AesLib)