#include <AesLib/AesXtsDecryptor.h>
#include <AesLib/detail/AesGFMul.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength, typename TweakHandler>
AesXtsDecryptor<KeyLength, TweakHandler>::AesXtsDecryptor() :
    detail::AesXtsDecryptorImpl<TweakHandler>(detail::BuildDecryptor<KeyLength>(),
        detail::BuildEncryptor<KeyLength>()) {}

template<int KeyLength, typename TweakHandler>
AesXtsDecryptor<KeyLength, TweakHandler>::AesXtsDecryptor(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize) :
    detail::AesXtsDecryptorImpl<TweakHandler>(detail::BuildDecryptor<KeyLength>(pKey1, key1Size),
        detail::BuildEncryptor<KeyLength>(pKey2, key2Size),
        sectSize) {}

template<int KeyLength, typename TweakHandler>
AesXtsDecryptor<KeyLength, TweakHandler>::~AesXtsDecryptor() = default;

template class AesXtsDecryptor<128, detail::AesXtsTweakHandler>;
template class AesXtsDecryptor<192, detail::AesXtsTweakHandler>;
template class AesXtsDecryptor<256, detail::AesXtsTweakHandler>;

template class AesXtsDecryptor<128, detail::AesXtsNTweakHandler>;
template class AesXtsDecryptor<192, detail::AesXtsNTweakHandler>;
template class AesXtsDecryptor<256, detail::AesXtsNTweakHandler>;

} // namespace crypto
