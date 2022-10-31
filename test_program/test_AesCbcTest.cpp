#include "test_AesCbcTest.h"
#include "test_TestData.h"
#include "test_CbcEncData.h"
#include <AesLib/Aes128.h>
#include <vector>

namespace crypto {
namespace test {

void TestAesCbcMode() {
    constexpr auto dataSize = sizeof(crypto::test::g_TestData);
    crypto::AesCbcEncryptor128 encryptor(crypto::test::g_TestKey1, 0x10, crypto::test::g_TestKey2, 0x10);
    crypto::AesCbcDecryptor128 decryptor(crypto::test::g_TestKey1, 0x10, crypto::test::g_TestKey2, 0x10);
    std::vector<uint8_t> buf(dataSize);

    /* Encrypt data. */
    encryptor.EncryptData(buf.data(), dataSize, crypto::test::g_TestData, dataSize);

    /* Check data. */
    if(std::memcmp(buf.data(), crypto::test::g_CbcEncData, dataSize)) {
        std::printf("Enc Data Different!\n");
        return;
    }

    /* Decrypt data. */
    decryptor.DecryptData(buf.data(), dataSize, buf.data(), dataSize);

    /* Check data. */
    if(std::memcmp(buf.data(), crypto::test::g_TestData, dataSize)) {
        std::printf("Enc Data Different!\n");
        return;
    }

    std::printf("Test Passed!\n");
}

} // namespace test
} // namespace crypto
