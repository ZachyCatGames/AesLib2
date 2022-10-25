#include <AesCbcDecryptor128.h>

namespace crypto {

AesCbcDecryptor128::AesCbcDecryptor128() = default;

AesCbcDecryptor128::AesCbcDecryptor128(const void* pKey, size_t keySize, const void* pIv, size_t ivSize) :
    m_EcbEncrypter(pKey, keySize)
{
    std::memcpy(m_AesIv, pIv, 0x10);
}

AesCbcDecryptor128::~AesCbcDecryptor128() = default;

void AesCbcDecryptor128::Initialize(const void* pKey, size_t keySize, const void* pIv, size_t ivSize) {
    /* Initialize ECB encrypter. */
    m_EcbEncrypter.Initialize(pKey, keySize);

    /* Copy iv. */
    std::memcpy(m_AesIv, pIv, 0x10);
}

void AesCbcDecryptor128::Finalize() {
    /* Finalize ECB encrypter. */
    m_EcbEncrypter.Finalize();
}

crypto::AesResult AesCbcDecryptor128::DecryptData(void* pOut, size_t outSize, const void* pIn, size_t size) {
    uint8_t tmp[Aes128BlockLength];
    uint8_t iv_buf[Aes128BlockLength];
    uint8_t nextIv[Aes128BlockLength];
    size_t pos = 0;

    /* Assert that data is aligned to 0x10 bytes */
    if(size % Aes128BlockLength != 0) {
        printf("Error: Size must be aligned to 0x10 bytes");
        return crypto::AesResult::NotAligned;
    }

    /* Loop until all data is decrypted */
    for(size_t i = 0; i < size; i += Aes128BlockLength) {
        /* Copy encrypted data to next iv */
        std::memcpy(nextIv, static_cast<const uint8_t*>(pIn) + pos, Aes128BlockLength);

        /* Decrypt data with key */
        m_EcbEncrypter.DecryptBlock(tmp, static_cast<const uint8_t*>(pIn) + pos);

        /* XOR data with iv */
        for(uint8_t i = 0; i < Aes128BlockLength; i++) {
            (static_cast<uint8_t*>(pOut) + pos)[i] = tmp[i] ^ m_AesIv[i];
        }

        /* Copy next iv to iv */
        std::memcpy(m_AesIv, nextIv, Aes128BlockLength);

        /* Increment Position */
        pos += Aes128BlockLength;
    }

    /* Return */
    return crypto::AesResult::Success;
}

} // namespace crypto
