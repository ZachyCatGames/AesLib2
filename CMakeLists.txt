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

#set(CMAKE_SYSTEM_PROCESSOR "aarch64")

if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
    # Set platform sources.
    set(PLATFORM_SPECIFIC_SRC
        "include/AesLib/detail/arch/amd64/AesDecryptImpl.cpu-amd64.h" "source/detail/arch/amd64/AesDecryptImpl.cpu-amd64.cpp"
        "include/AesLib/detail/arch/amd64/AesEncryptImpl.cpu-amd64.h" "source/detail/arch/amd64/AesEncryptImpl.cpu-amd64.cpp"
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
        "include/AesLib/detail/arch/aarch64/AesDecryptImpl.cpu-aarch64.h" 
        "source/detail/arch/aarch64/AesDecryptImpl128.cpu-aarch64.S"
        "source/detail/arch/aarch64/AesDecryptImpl192.cpu-aarch64.S"
        "source/detail/arch/aarch64/AesDecryptImpl256.cpu-aarch64.S"
        "include/AesLib/detail/arch/aarch64/AesEncryptImpl.cpu-aarch64.h" 
        "source/detail/arch/aarch64/AesEncryptImpl128.cpu-aarch64.S"
        "source/detail/arch/aarch64/AesEncryptImpl192.cpu-aarch64.S"
        "source/detail/arch/aarch64/AesEncryptImpl256.cpu-aarch64.S"
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
    "include/AesLib/detail/AesDecryptImpl.cpu-generic.h" "source/detail/AesDecryptImpl.cpu-generic.cpp"
    "include/AesLib/detail/AesEncryptImpl.cpu-generic.h" "source/detail/AesEncryptImpl.cpu-generic.cpp"
    "include/AesLib/detail/AesExpandKeyImpl.h" "source/detail/AesExpandKeyImpl.cpp"
    "include/AesLib/detail/AesGFMul.h" "source/detail/AesGFMul.cpp"
    "include/AesLib/detail/AesXtsTweakHandler.h" "source/detail/AesXtsTweakHandler.cpp"
    "include/AesLib/detail/IAesDecryptor.h"
    "include/AesLib/detail/IAesEncryptor.h"

    "include/AesLib/Aes.h"
    "include/AesLib/AesCommon.h"
    "include/AesLib/detail/AesLookupTables.h"
    "include/AesLib/AesEcbDecryptor.h" "source/AesEcbDecryptor.cpp"
    "include/AesLib/AesEcbEncryptor.h" "source/AesEcbEncryptor.cpp"
    "include/AesLib/AesCbcDecryptor.h" "source/AesCbcDecryptor.cpp"
    "include/AesLib/AesCbcEncryptor.h" "source/AesCbcEncryptor.cpp"
    "include/AesLib/AesXtsDecryptor.h" "source/AesXtsDecryptor.cpp"
    "include/AesLib/AesXtsEncryptor.h" "source/AesXtsEncryptor.cpp"
    "include/AesLib/AesCtr.h" "source/AesCtr.cpp" 

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
    "test_program/test_AesEcbSampleVector.h" "test_program/test_AesEcbSampleVector.cpp"
)
target_link_libraries(AesLibTest PUBLIC AesLib)