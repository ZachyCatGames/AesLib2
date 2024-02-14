#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesEncryptor.h>
#include <memory>

namespace crypto {

template<int KeyLength>
class AesEcbEncryptor {
public:
    static constexpr int KeySize = KeyLength / 8;

public:
    AesEcbEncryptor();
    AesEcbEncryptor(const void* pKey, size_t keySize);
    ~AesEcbEncryptor();

    void Initialize(const void* pKey, size_t keySize);
    void Finalize();

    AesResult EncryptBlock(void* pOut, const void* pIn);
    AesResult EncryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize);

private:
    std::unique_ptr<detail::IAesEncryptor<KeyLength>> m_pImpl;
};

using AesEcbEncryptor128 = AesEcbEncryptor<128>;
using AesEcbEncryptor192 = AesEcbEncryptor<192>;
using AesEcbEncryptor256 = AesEcbEncryptor<256>;

} // namespace crypto