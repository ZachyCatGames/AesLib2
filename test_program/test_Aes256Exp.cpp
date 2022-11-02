#include "test_Aes256Exp.h"
#include <AesLib/detail/AesExpandKeyImpl256.h>
#include <AesLib/detail/AesExpandKeyImpl128.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <chrono>

namespace crypto {
namespace test {

constexpr uint8_t g_TestKey128[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

constexpr uint8_t g_TestKey256[] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

void TestExperimentalAes256() {
    uint32_t keyData[14 * 8];

    auto start = std::chrono::high_resolution_clock::now();

    for(int i = 0; i < 10000000; ++i) {
        crypto::detail::AesExpandKeyImpl256(keyData);
    }

    auto end = std::chrono::high_resolution_clock::now();

    std::cout << "Time: " << end - start << std::endl;
    return;

    std::memcpy(keyData, g_TestKey256, 32);
    crypto::detail::AesExpandKeyImpl256(keyData);
    for(int i = 0; i < 15; ++i) {
        printf("%02d ", i);
        for(int j = 0; j < 16; ++j) {
            printf("%02x", *(reinterpret_cast<uint8_t*>(keyData) + i * 16 + j));
        }

        printf("\n");
    }
}

} // namespace test
} // namespace crypto
