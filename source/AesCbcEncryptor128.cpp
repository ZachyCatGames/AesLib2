#include <AesCbcEncryptor128.h>

namespace crypto {

AesCbcEncryptor128::AesCbcEncryptor128() = default;

AesCbcEncryptor128::AesCbcEncryptor128(const void* pKey, size_t keySize, const void* pIv, size_t ivSize) :
    m_EcbEncrypter(pKey, keySize)
{
    std::memcpy(m_AesIv, pIv, 0x10);
}

AesCbcEncryptor128::~AesCbcEncryptor128() = default;

void AesCbcEncryptor128::Initialize(const void* pKey, size_t keySize, const void* pIv, size_t ivSize) {
    /* Initialize ECB encrypter. */
    m_EcbEncrypter.Initialize(pKey, keySize);

    /* Copy iv. */
    std::memcpy(m_AesIv, pIv, 0x10);
}

void AesCbcEncryptor128::Finalize() {
    /* Finalize ECB encrypter. */
    m_EcbEncrypter.Finalize();
}

crypto::AesResult AesCbcEncryptor128::EncryptData(void* pOut, size_t outSize, const void* pIn, size_t size) {
    uint8_t tmp[Aes128BlockLength];
    uint8_t iv_buf[Aes128BlockLength];
    size_t pos = 0;

    /* Assert that data is aligned to 0x10 bytes */
    if(size % Aes128BlockLength != 0) {
        printf("Error: Size must be aligned to 0x10 bytes");
        return crypto::AesResult::NotAligned;
    }

    /* Loop until all data is encrypted */
    for(size_t i = 0; i < size; i += Aes128BlockLength) {
        /* Copy input at current position */
        std::memcpy(tmp, static_cast<const uint8_t*>(pIn) + pos, Aes128BlockLength);

        /* XOR Input with IV */
        for(uint8_t i = 0; i < 4; i++) {
            reinterpret_cast<uint32_t*>(tmp)[i] ^= reinterpret_cast<uint32_t*>(m_AesIv)[i];
        }

        /* Encrypt data with key */
        m_EcbEncrypter.EncryptBlock(static_cast<uint8_t*>(pOut) + pos, tmp);

        /* Copy encrypted data to iv_buf */
        std::memcpy(m_AesIv, static_cast<uint8_t*>(pOut) + pos, Aes128BlockLength);

        /* Increment Position */
        pos += Aes128BlockLength;
    }

    /* Return */
    return crypto::AesResult::Success;
}

} // namespace crypto
