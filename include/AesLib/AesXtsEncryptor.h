#include <AesLib/AesCommon.h>
#include <AesLib/detail/AesXtsTweakHandler.h>
#include <AesLib/detail/AesXtsNTweakHandler.h>
#include <AesLib/detail/AesXtsEncryptorImpl.h>
#include <cstdint>
#include <cstddef>

namespace crypto {

template<int KeyLength, typename TweakHandler>
class AesXtsEncryptor : public detail::AesXtsEncryptorImpl<TweakHandler> {
public:
    static constexpr int KeySize = KeyLength / 8;
public:
    AesXtsEncryptor();
    AesXtsEncryptor(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize);
    ~AesXtsEncryptor();
}; // class AesXtsEncryptor

using AesXtsEncryptor128 = AesXtsEncryptor<128, crypto::detail::AesXtsTweakHandler>;
using AesXtsEncryptor192 = AesXtsEncryptor<192, crypto::detail::AesXtsTweakHandler>;
using AesXtsEncryptor256 = AesXtsEncryptor<256, crypto::detail::AesXtsTweakHandler>;

using AesXtsNEncryptor128 = AesXtsEncryptor<128, crypto::detail::AesXtsNTweakHandler>;
using AesXtsNEncryptor192 = AesXtsEncryptor<192, crypto::detail::AesXtsNTweakHandler>;
using AesXtsNEncryptor256 = AesXtsEncryptor<256, crypto::detail::AesXtsNTweakHandler>;

} // namespace crypto
