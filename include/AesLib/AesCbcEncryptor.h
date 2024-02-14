#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/AesCbcEncryptorImpl.h>

namespace crypto {

template<int KeyLength>
class AesCbcEncryptor : public detail::AesCbcEncryptorImpl {
public:
    static constexpr int KeySize = KeyLength / 8;
public:
    AesCbcEncryptor();
    AesCbcEncryptor(const void* pKey, size_t keySize, const void* pIv, size_t ivSize);
    ~AesCbcEncryptor();
}; // class AesCbcEncryptor

using AesCbcEncryptor128 = AesCbcEncryptor<128>;
using AesCbcEncryptor192 = AesCbcEncryptor<192>;
using AesCbcEncryptor256 = AesCbcEncryptor<256>;

} // namespace crypto
