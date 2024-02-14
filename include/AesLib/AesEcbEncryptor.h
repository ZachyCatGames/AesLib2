#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/AesEcbEncryptorImpl.h>

namespace crypto {

template<int KeyLength>
class AesEcbEncryptor : public detail::AesEcbEncryptorImpl {
public:
    static constexpr int KeySize = KeyLength / 8;
public:
    AesEcbEncryptor();
    AesEcbEncryptor(const void* pKey, size_t keySize);
    ~AesEcbEncryptor();
}; // class AesEcbEncryptor

using AesEcbEncryptor128 = AesEcbEncryptor<128>;
using AesEcbEncryptor192 = AesEcbEncryptor<192>;
using AesEcbEncryptor256 = AesEcbEncryptor<256>;

} // namespace crypto