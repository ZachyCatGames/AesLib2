#include "test_AesEcbSampleVector.h"
#include <cstdint>
#include <AesLib/Aes128.h>

namespace crypto {
namespace test {

namespace {

constexpr uint8_t Key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

constexpr uint8_t Data[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

constexpr uint8_t EncData128[] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
};

constexpr uint8_t EncData192[] = {
    0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91
};

constexpr uint8_t EncData256[] = {
    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
};

} // namespace

void TestAes128SampleVector() {
    uint8_t tmp[16];
    crypto::AesEcbEncryptor128 encryptor(Key, 16);
    crypto::AesEcbDecryptor128 decryptor(Key, 16);

    /* Encrypt data. */
    encryptor.EncryptData(tmp, 16, Data, 16);

    /* Check data. */
    if(std::memcmp(tmp, EncData128, 16)) {
        std::printf("EncData Diff!\n");
        return;
    }

    /* Decrypt data. */
    decryptor.DecryptData(tmp, 16, tmp, 16);

    /* Check data. */
    if(std::memcmp(tmp, Data, 16)) {
        std::printf("DecData Diff!\n");
        return;
    }

    printf("Test Passed!\n");
}

void TestAes192SampleVector() {
    uint8_t tmp[16];
    crypto::AesEcbEncryptor192 encryptor(Key, 24);
    crypto::AesEcbDecryptor192 decryptor(Key, 24);

    /* Encrypt data. */
    encryptor.EncryptData(tmp, 16, Data, 16);

    /* Check data. */
    if(std::memcmp(tmp, EncData192, 16)) {
        std::printf("EncData Diff!\n");
        return;
    }

    /* Decrypt data. */
    decryptor.DecryptData(tmp, 16, tmp, 16);

    /* Check data. */
    if(std::memcmp(tmp, Data, 16)) {
        std::printf("DecData Diff!\n");
        return;
    }

    printf("Test Passed!\n");
}

void TestAes256SampleVector() {
    uint8_t tmp[16];
    crypto::AesEcbEncryptor256 encryptor(Key, 32);
    crypto::AesEcbDecryptor256 decryptor(Key, 32);

    /* Encrypt data. */
    encryptor.EncryptData(tmp, 16, Data, 16);

    /* Check data. */
    if(std::memcmp(tmp, EncData256, 16)) {
        std::printf("EncData Diff!\n");
        return;
    }

    /* Decrypt data. */
    decryptor.DecryptData(tmp, 16, tmp, 16);

    /* Check data. */
    if(std::memcmp(tmp, Data, 16)) {
        std::printf("DecData Diff!\n");
        return;
    }

    printf("Test Passed!\n");
}

} // namespace test
} // namespace crypto
