#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesDecryptor.h>

namespace crypto {
namespace detail {

class AesEcbDecryptorImpl {
public:
    AesEcbDecryptorImpl(UniqueDecryptor&& pDec);
    ~AesEcbDecryptorImpl();

    void Initialize(const void* pKey, size_t keySize);
    void Finalize();

    AesResult DecryptBlock(void* pOut, const void* pIn);
    AesResult DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize);
private:
    UniqueDecryptor m_pImpl;
}; // class AesEcbDecryptorImpl

} // namespace detail
} // namespace crypto
