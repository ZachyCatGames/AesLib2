#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesEncryptor.h>
#include <cstdint>

namespace crypto {
namespace detail {

class AesCbcEncryptorImpl {
public:
    static constexpr int IvSize = AesBlockLength;
public:
    AesCbcEncryptorImpl(UniqueEncryptor&& pEnc);
    AesCbcEncryptorImpl(UniqueEncryptor&& pEnc, const void* pIv, size_t ivSize);
    ~AesCbcEncryptorImpl();

    void Initialize(const void* pKey, size_t keySize, const void* pIv, size_t ivSize);
    void Finalize();
public:
    /* CBC Encrypt Data */
    AesResult EncryptData(void* pOut, size_t outSize, const void* pIn, size_t size);
private:
    UniqueEncryptor&& m_pEncryptor;
    uint8_t m_Iv[16];
}; // class AesCbcEncryptorImpl

} // namespace detail
} // namespace crypto
