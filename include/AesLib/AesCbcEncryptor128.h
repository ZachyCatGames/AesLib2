#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesEncryptor128.h>
#include <cstdint>
#include <memory>

namespace crypto {

class AesCbcEncryptor128 {
public:
    AesCbcEncryptor128();
    AesCbcEncryptor128(const void* pKey, size_t keySize, const void* pIv, size_t ivSize);
    ~AesCbcEncryptor128();

    void Initialize(const void* pKey, size_t keySize, const void* pIv, size_t ivSize);
    void Finalize();

public:
    /* CBC Encrypt Data */
    crypto::AesResult EncryptData(void* pOut, size_t outSize, const void* pIn, size_t size);

private:
    std::unique_ptr<crypto::detail::IAesEncryptor128> m_pEncryptor;
    uint8_t m_AesIv[16];
};

} // namespace crypto
