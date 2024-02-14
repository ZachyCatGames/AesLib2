#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesDecryptor.h>
#include <cstdint>

namespace crypto {
namespace detail {

class AesCbcDecryptorImpl {
public:
    static constexpr int IvSize = AesBlockLength;
public:
    AesCbcDecryptorImpl(UniqueDecryptor&& pDec);
    AesCbcDecryptorImpl(UniqueDecryptor&& pDec, const void* pIv, size_t ivSize);
    ~AesCbcDecryptorImpl();

    void Initialize(const void* pKey, size_t keySize, const void* pIv, size_t ivSize);
    void Finalize();
public:
    /* CBC Decrypt Data */
    AesResult DecryptData(void* pOut, size_t outSize, const void* pIn, size_t size);
private:
    UniqueDecryptor m_pDecryptor;
    uint8_t m_Iv[16];
}; // class AesCbcDecryptorImpl

} // namespace detail
} // namespace crypto
