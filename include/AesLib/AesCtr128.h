#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/AesEcbEncryptor128.h>
#include <AesLib/detail/IAesEncryptor128.h>
#include <cstdint>

namespace crypto {

class AesCtr128 {
public:
    AesCtr128();
    AesCtr128(const void* pKey, size_t keySize, const void* pCtr, size_t ctrSize);
    ~AesCtr128();

    void Initialize(const void* pKey, size_t keySize, const void* pCtr, size_t ctrSize);

    void Finalize();

    /* Set counter. */
    void SetCounter(const void* pCtr, size_t ctrSize);

    /* CTR Crypt Block */
    crypto::AesResult CryptBlock(void* pOut, const void* pIn);

    /* CTR Crypt Data */
    crypto::AesResult CryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize);

private:
    crypto::AesEcbEncryptor128 m_EcbEncrypter;
    uint8_t m_AesCounter[16];
};

} // namespace crypto
