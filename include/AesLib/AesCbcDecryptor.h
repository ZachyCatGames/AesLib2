#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/AesCbcDecryptorImpl.h>

namespace crypto {

template<int KeyLength>
class AesCbcDecryptor : public detail::AesCbcDecryptorImpl {
public:
    static constexpr int KeySize = KeyLength / 8;
public:
    AesCbcDecryptor();
    AesCbcDecryptor(const void* pKey, size_t keySize, const void* pIv, size_t ivSize);
    ~AesCbcDecryptor();
}; // class AesCbcDecryptor

using AesCbcDecryptor128 = AesCbcDecryptor<128>;
using AesCbcDecryptor192 = AesCbcDecryptor<192>;
using AesCbcDecryptor256 = AesCbcDecryptor<256>;

} // namespace crypto
