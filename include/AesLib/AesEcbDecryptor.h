#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesDecryptor.h>
#include <memory>

namespace crypto {

template<int KeyLength>
class AesEcbDecryptor {
public:
    static constexpr int KeySize = KeyLength / 8;

public:
    AesEcbDecryptor();
    AesEcbDecryptor(const void* pKey, size_t keySize);
    ~AesEcbDecryptor();

    void Initialize(const void* pKey, size_t keySize);
    void Finalize();

    AesResult DecryptBlock(void* pOut, const void* pIn);
    AesResult DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize);

private:
    std::unique_ptr<detail::IAesDecryptor<KeyLength>> m_pImpl;
};

using AesEcbDecryptor128 = AesEcbDecryptor<128>;
using AesEcbDecryptor192 = AesEcbDecryptor<192>;
using AesEcbDecryptor256 = AesEcbDecryptor<256>;

} // namespace crypto
