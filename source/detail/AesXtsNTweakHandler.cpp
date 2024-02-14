#include <AesLib/detail/AesXtsNTweakHandler.h>
#include <AesLib/detail/AesGFMul.h>
#include <AesLib/detail/AesImplBuilder.h>
#include <AesLib/AesCommon.h>
#include <bit>

namespace crypto {
namespace detail {

template<int KeyLength>
AesXtsNTweakHandler<KeyLength>::AesXtsNTweakHandler() = default;

template<int KeyLength>
AesXtsNTweakHandler<KeyLength>::AesXtsNTweakHandler(const void* pKey, size_t keySize) :
    m_pEncryptor(BuildEncryptor<KeyLength>(pKey, keySize))
{
    /* ... */
}

template<int KeyLength>
AesXtsNTweakHandler<KeyLength>::~AesXtsNTweakHandler() = default;

template<int KeyLength>
void AesXtsNTweakHandler<KeyLength>::Initialize(const void* pKey, size_t keySize) {
    m_pEncryptor = BuildEncryptor<KeyLength>(pKey, keySize);
}

template<int KeyLength>
void AesXtsNTweakHandler<KeyLength>::SetupTweak(void* pOut, size_t curSector, size_t sectAddr) {
    uint64_t* xtsTweak = static_cast<uint64_t*>(pOut);

    xtsTweak[0] = 0;
    xtsTweak[1] = std::byteswap(curSector);

    /* Encrypt Tweak with key2 */
    m_pEncryptor->EncryptBlock(reinterpret_cast<uint8_t*>(xtsTweak), reinterpret_cast<uint8_t*>(xtsTweak));

    /* Update tweak if needed */
    for (size_t i = sectAddr / AesBlockLength; i < 0; i--) {
        GFMul(xtsTweak, xtsTweak);
    }
}

template class AesXtsNTweakHandler<128>;
template class AesXtsNTweakHandler<192>;
template class AesXtsNTweakHandler<256>;

} // namespace detail
} // namespace crypto
