# CMakeList.txt : CMake project for AesLib, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)
project(AesLib)

enable_language(CXX ASM)

# Set standard.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED yes)

# Add include dir
include_directories(include)

set(CMAKE_SYSTEM_PROCESSOR "aarch64")

if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
    # Set platform sources.
    set(PLATFORM_SPECIFIC_SRC
        "include/AesLib/detail/arch/amd64/AesDecryptImpl128.cpu-amd64.h" "source/detail/arch/amd64/AesDecryptImpl128.cpu-amd64.cpp"
        "include/AesLib/detail/arch/amd64/AesEncryptImpl128.cpu-amd64.h" "source/detail/arch/amd64/AesEncryptImpl128.cpu-amd64.cpp"
        "include/AesLib/detail/AesImplBuilder.h" "source/detail/arch/amd64/AesImplBuilder.cpu-amd64.cpp"
        "include/AesLib/detail/arch/amd64/AesSimdKeyExpansion.cpu-amd64.h" "source/detail/arch/amd64/AesSimdKeyExpansion.cpu-amd64.cpp"
        "include/AesLib/detail/AesXorBlock128.h" "source/detail/arch/amd64/AesXorBlock128.cpu-amd64.cpp"
        "include/AesLib/detail/arch/amd64/CpuId.cpu-amd64.h" "source/detail/arch/amd64/CpuId.cpu-amd64.cpp"
        "include/AesLib/detail/arch/amd64/ExtensionSupport.cpu-amd64.h" "source/detail/arch/amd64/ExtensionSupport.cpu-amd64.cpp"
    )

    # Add compile flags.
    add_compile_options(-maes)
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64")
    # Set platform sources.
    set(PLATFORM_SPECIFIC_SRC
        "include/AesLib/detail/arch/aarch64/AesDecryptImpl128.cpu-aarch64.h" "source/detail/arch/aarch64/AesDecryptImpl128.cpu-aarch64.cpp" "source/detail/arch/aarch64/AesDecryptImpl128.cpu-aarch64.S"
        "include/AesLib/detail/arch/aarch64/AesEncryptImpl128.cpu-aarch64.h" "source/detail/arch/aarch64/AesEncryptImpl128.cpu-aarch64.cpp" "source/detail/arch/aarch64/AesEncryptImpl128.cpu-aarch64.S"
        "include/AesLib/detail/AesImplBuilder.h" "source/detail/arch/aarch64/AesImplBuilder.cpu-aarch64.cpp"
        "include/AesLib/detail/arch/aarch64/ExtensionSupport.cpu-aarch64.h" "source/detail/arch/aarch64/ExtensionSupport.cpu-aarch64.cpp"
        "include/AesLib/detail/AesXorBlock128.h" "source/detail/arch/aarch64/AesXorBlock128.cpu-aarch64.S"
    )

    # Add compile flags.
    add_compile_options(-mcpu=cortex-a57+crypto)
else()
    # Set platform sources.
    set(PLATFORM_SPECIFIC_SRC
        "include/AesLib/detail/AesImplBuilder.h" "source/detail/AesImplBuilder.cpu-generic.cpp"
        "include/AesLib/detail/AesXorBlock128.h" "source/detail/AesXorBlock128.cpu-generic.cpp"
    )
endif()
# 

# Add source files to lib.
add_library(AesLib STATIC
    "include/AesLib/detail/AesByteSwap.h"
    "include/AesLib/detail/AesDecryptImpl128.cpu-generic.h" "source/detail/AesDecryptImpl128.cpu-generic.cpp"
    "include/AesLib/detail/AesEncryptImpl128.cpu-generic.h" "source/detail/AesEncryptImpl128.cpu-generic.cpp"
    "include/AesLib/detail/AesExpandKeyImpl.h" "source/detail/AesExpandKeyImpl.cpp"
    "include/AesLib/detail/AesExpandKeyImpl128.h" "source/detail/AesExpandKeyImpl128.cpp"
    "include/AesLib/detail/AesExpandKeyImpl256.h" "source/detail/AesExpandKeyImpl256.cpp"
    "include/AesLib/detail/AesGFMul.h" "source/detail/AesGFMul.cpp"
    "include/AesLib/detail/AesXtsTweakHandler.h" "source/detail/AesXtsTweakHandler.cpp"
    "include/AesLib/detail/IAesDecryptor128.h"
    "include/AesLib/detail/IAesEncryptor128.h"

    "include/AesLib/Aes128.h"
    "include/AesLib/AesCommon.h"
    "include/AesLib/detail/AesLookupTables128.h"
    "include/AesLib/AesEcbDecryptor128.h" "source/AesEcbDecryptor128.cpp"
    "include/AesLib/AesEcbEncryptor128.h" "source/AesEcbEncryptor128.cpp"
    "include/AesLib/AesCbcDecryptor128.h" "source/AesCbcDecryptor128.cpp"
    "include/AesLib/AesCbcEncryptor128.h" "source/AesCbcEncryptor128.cpp"
    "include/AesLib/AesXtsDecryptor128.h" "source/AesXtsDecryptor128.cpp"
    "include/AesLib/AesXtsEncryptor128.h" "source/AesXtsEncryptor128.cpp"
    "include/AesLib/AesCtr128.h" "source/AesCtr128.cpp" 

    ${PLATFORM_SPECIFIC_SRC}
)
target_include_directories(AesLib PUBLIC include)

# Create test exe.
add_executable(AesLibTest
    "test_program/test_Main.cpp"
    "test_program/test_TestData.h"
    "test_program/test_EcbEncData.h"
    "test_program/test_AesEcbTest.h" "test_program/test_AesEcbTest.cpp"
    "test_program/test_AesCbcTest.h" "test_program/test_AesCbcTest.cpp"
    "test_program/test_Aes256Exp.h" "test_program/test_Aes256Exp.cpp"
)
target_link_libraries(AesLibTest PUBLIC AesLib)