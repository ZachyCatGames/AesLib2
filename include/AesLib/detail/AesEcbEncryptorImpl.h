#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesEncryptor.h>
#include <memory>

namespace crypto {
namespace detail {

class AesEcbEncryptorImpl {
public:
    AesEcbEncryptorImpl(UniqueEncryptor&& pEnc);
    ~AesEcbEncryptorImpl();

    void Initialize(const void* pKey, size_t keySize);
    void Finalize();

    AesResult EncryptBlock(void* pOut, const void* pIn);
    AesResult EncryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize);
private:
    UniqueEncryptor m_pImpl;
}; // class AesEcbEncryptorImpl

} // namespace detail
} // namespace crypto