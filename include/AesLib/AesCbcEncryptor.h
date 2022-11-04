#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/IAesEncryptor.h>
#include <cstdint>
#include <memory>

namespace crypto {

template<int KeyLength>
class AesCbcEncryptor {
public:
    static constexpr int KeySize = KeyLength / 8;
    static constexpr int IvSize = crypto::AesBlockLength;

public:
    AesCbcEncryptor();
    AesCbcEncryptor(const void* pKey, size_t keySize, const void* pIv, size_t ivSize);
    ~AesCbcEncryptor();

    void Initialize(const void* pKey, size_t keySize, const void* pIv, size_t ivSize);
    void Finalize();

public:
    /* CBC Encrypt Data */
    crypto::AesResult EncryptData(void* pOut, size_t outSize, const void* pIn, size_t size);

private:
    std::unique_ptr<crypto::detail::IAesEncryptor<KeyLength>> m_pEncryptor;
    uint8_t m_AesIv[16];
};

using AesCbcEncryptor128 = AesCbcEncryptor<128>;
using AesCbcEncryptor192 = AesCbcEncryptor<192>;
using AesCbcEncryptor256 = AesCbcEncryptor<256>;

} // namespace crypto
