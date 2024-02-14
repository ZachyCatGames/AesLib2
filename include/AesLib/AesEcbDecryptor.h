#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/AesEcbDecryptorImpl.h>

namespace crypto {

template<int KeyLength>
class AesEcbDecryptor : public detail::AesEcbDecryptorImpl {
public:
    static constexpr int KeySize = KeyLength / 8;
public:
    AesEcbDecryptor();
    AesEcbDecryptor(const void* pKey, size_t keySize);
    ~AesEcbDecryptor();
}; // class AesEcbDecryptor

using AesEcbDecryptor128 = AesEcbDecryptor<128>;
using AesEcbDecryptor192 = AesEcbDecryptor<192>;
using AesEcbDecryptor256 = AesEcbDecryptor<256>;

} // namespace crypto
