#pragma once
#include <AesLib/AesCommon.h>
#include <AesLib/detail/AesCtrImpl.h>

namespace crypto {

template<int KeyLength>
class AesCtr : public detail::AesCtrImpl {
public:
    static constexpr int KeySize = KeyLength / 8;
public:
    AesCtr();
    AesCtr(const void* pKey, size_t keySize, const void* pCtr, size_t ctrSize);
    ~AesCtr();
};

using AesCtr128 = AesCtr<128>;
using AesCtr192 = AesCtr<192>;
using AesCtr256 = AesCtr<256>;

} // namespace crypto
