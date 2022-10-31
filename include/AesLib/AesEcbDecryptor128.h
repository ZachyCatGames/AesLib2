#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesDecryptor128.h>
#include <memory>

namespace crypto {

class AesEcbDecryptor128 {
public:
    AesEcbDecryptor128();
    AesEcbDecryptor128(const void* pKey, size_t keySize);
    ~AesEcbDecryptor128();

    void Initialize(const void* pKey, size_t keySize);
    void Finalize();

    crypto::AesResult DecryptBlock(void* pOut, const void* pIn);
    crypto::AesResult DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize);

private:
    std::unique_ptr<crypto::detail::IAesDecryptor128> m_pImpl;
};

} // namespace crypto
