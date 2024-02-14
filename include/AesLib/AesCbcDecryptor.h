#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesDecryptor.h>
#include <cstdint>
#include <memory>

namespace crypto {

template<int KeyLength>
class AesCbcDecryptor {
public:
    static constexpr int KeySize = KeyLength / 8;
    static constexpr int IvSize = AesBlockLength;

public:
    AesCbcDecryptor();
    AesCbcDecryptor(const void* pKey, size_t keySize, const void* pIv, size_t ivSize);
    ~AesCbcDecryptor();

    void Initialize(const void* pKey, size_t keySize, const void* pIv, size_t ivSize);
    void Finalize();

public:
    /* CBC Decrypt Data */
    AesResult DecryptData(void* pOut, size_t outSize, const void* pIn, size_t size);

private:
    std::unique_ptr<detail::IAesDecryptor<KeyLength>> m_pDecryptor;
    uint8_t m_AesIv[16];
};

using AesCbcDecryptor128 = AesCbcDecryptor<128>;
using AesCbcDecryptor192 = AesCbcDecryptor<192>;
using AesCbcDecryptor256 = AesCbcDecryptor<256>;

} // namespace crypto
