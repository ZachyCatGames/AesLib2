#pragma once

#define AES_ENABLE_HW_ACCEL true
#define AES_WIPE_KEYS_ON_DESTRUCTION false

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <array>
#include <cstring>

constexpr static inline size_t Aes128BlockLength = 0x10;
constexpr static inline size_t Aes128RoundKeyArraySize = (sizeof(uint8_t) * 11 * 16);

//#define ALIGN(amount) __attribute__((aligned(amount)))
#define ALIGN(amount) __declspec(align(amount))

enum Aes128Result {
    Result_Success = 0,
    Result_DataNotAligned128 = 1,
    Result_NotImplemented = 2,
};

namespace crypto {

static constexpr size_t AesBlockLength = 0x10;

enum class AesResult {
    Success = 0,
    NotAligned,
    OutTooSmall
};

}
