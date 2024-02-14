#include <AesLib/AesXtsEncryptor.h>
#include <AesLib/detail/AesGFMul.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength, typename TweakHandler>
AesXtsEncryptor<KeyLength, TweakHandler>::AesXtsEncryptor() :
    detail::AesXtsEncryptorImpl<TweakHandler>(detail::BuildEncryptor<KeyLength>(),
        detail::BuildEncryptor<KeyLength>()) {}

template<int KeyLength, typename TweakHandler>
AesXtsEncryptor<KeyLength, TweakHandler>::AesXtsEncryptor(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize) :
    detail::AesXtsEncryptorImpl<TweakHandler>(detail::BuildEncryptor<KeyLength>(pKey1, key1Size),
        detail::BuildEncryptor<KeyLength>(pKey2, key2Size),
        sectSize) {}

template<int KeyLength, typename TweakHandler>
AesXtsEncryptor<KeyLength, TweakHandler>::~AesXtsEncryptor() = default;

template class AesXtsEncryptor<128, detail::AesXtsTweakHandler>;
template class AesXtsEncryptor<192, detail::AesXtsTweakHandler>;
template class AesXtsEncryptor<256, detail::AesXtsTweakHandler>;

template class AesXtsEncryptor<128, detail::AesXtsNTweakHandler>;
template class AesXtsEncryptor<192, detail::AesXtsNTweakHandler>;
template class AesXtsEncryptor<256, detail::AesXtsNTweakHandler>;

} // namespace crypto