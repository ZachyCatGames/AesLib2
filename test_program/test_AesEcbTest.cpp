#include "test_AesEcbTest.h"
#include "test_TestData.h"
#include "test_EcbEncData.h"
#include <vector>
#include <iostream>

namespace crypto {
namespace test {

void TestAesEcbMode() {
    constexpr auto dataSize = sizeof(crypto::test::g_TestData);
    std::vector<uint8_t> buf(dataSize);
    crypto::AesEcbEncryptor128 encryptor(crypto::test::g_TestKey1, 0x10);
    crypto::AesEcbDecryptor128 decryptor(crypto::test::g_TestKey1, 0x10);

    /* Encrypt data. */
    encryptor.EncryptData(buf.data(), dataSize, crypto::test::g_TestData, 0x10);

    /* Check data. */
    if(std::memcmp(buf.data(), crypto::test::g_EcbEncData, 0x10)) {
        std::printf("Enc Data Different!\n");
        return;
    }

    /* Decrypt data. */
    decryptor.DecryptData(buf.data(), dataSize, buf.data(), 0x10);

    /* Check data. */
    if(std::memcmp(buf.data(), crypto::test::g_TestData, 0x10)) {
        std::printf("Dec Data Different!\n");
        return;
    }

    std::printf("Test Passed!\n");
}

} // namespace test
} // namespace crypto
