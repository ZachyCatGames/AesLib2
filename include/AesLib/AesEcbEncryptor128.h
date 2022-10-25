#pragma once
#include <AesLib/detail/AesEncryptImpl128.h>

namespace crypto {

class AesEcbEncryptor128 {
public:
    AesEcbEncryptor128();
    AesEcbEncryptor128(const void* pKey, size_t keySize);
    ~AesEcbEncryptor128();

    void Initialize(const void* pKey, size_t keySize);
    void Finalize();

    crypto::AesResult EncryptBlock(void* pOut, const void* pIn);
    crypto::AesResult EncryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize);

private:
    crypto::detail::AesEncryptImpl128 m_Impl;
};

} // namespace crypto