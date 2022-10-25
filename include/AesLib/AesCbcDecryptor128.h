#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/AesEcbDecryptor128.h>
#include <cstdint>

namespace crypto {

class AesCbcDecryptor128 {
public:
    AesCbcDecryptor128();
    AesCbcDecryptor128(const void* pKey, size_t keySize, const void* pIv, size_t ivSize);
    ~AesCbcDecryptor128();

    void Initialize(const void* pKey, size_t keySize, const void* pIv, size_t ivSize);
    void Finalize();

public:
    /* CBC Decrypt Data */
    crypto::AesResult DecryptData(void* pOut, size_t outSize, const void* pIn, size_t size);

private:
    crypto::AesEcbDecryptor128 m_EcbEncrypter;
    uint8_t m_AesIv[16];
};

} // namespace crypto
