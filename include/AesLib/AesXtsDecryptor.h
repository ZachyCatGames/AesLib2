#include <AesLib/AesCommon.h>
#include <AesLib/detail/AesXtsDecryptorImpl.h>
#include <cstdint>
#include <cstddef>

namespace crypto {

template<int KeyLength, typename TweakHandler>
class AesXtsDecryptor : public detail::AesXtsDecryptorImpl<TweakHandler> {
public:
    static constexpr int KeySize = KeyLength / 8;
public:
    AesXtsDecryptor();
    AesXtsDecryptor(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize);
    ~AesXtsDecryptor();
}; // class AesXtsDecryptor

using AesXtsDecryptor128 = AesXtsDecryptor<128, detail::AesXtsTweakHandler>;
using AesXtsDecryptor192 = AesXtsDecryptor<192, detail::AesXtsTweakHandler>;
using AesXtsDecryptor256 = AesXtsDecryptor<256, detail::AesXtsTweakHandler>;

using AesXtsNDecryptor128 = AesXtsDecryptor<128, detail::AesXtsNTweakHandler>;
using AesXtsNDecryptor192 = AesXtsDecryptor<192, detail::AesXtsNTweakHandler>;
using AesXtsNDecryptor256 = AesXtsDecryptor<256, detail::AesXtsNTweakHandler>;

} // namespace crypto
