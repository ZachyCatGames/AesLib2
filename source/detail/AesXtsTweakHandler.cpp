#include <AesLib/detail/AesXtsTweakHandler.h>
#include <AesLib/detail/AesGFMul.h>
#include <AesLib/detail/AesImplBuilder.h>
#include <AesLib/AesCommon.h>

namespace crypto {
namespace detail {

template<int KeyLength>
AesXtsTweakHandler<KeyLength>::AesXtsTweakHandler() = default;

template<int KeyLength>
AesXtsTweakHandler<KeyLength>::AesXtsTweakHandler(const void* pKey, size_t keySize) :
    m_pEncryptor(BuildEncryptor<KeyLength>(pKey, keySize))
{
    /* ... */
}

template<int KeyLength>
AesXtsTweakHandler<KeyLength>::~AesXtsTweakHandler() = default;

template<int KeyLength>
void AesXtsTweakHandler<KeyLength>::Initialize(const void* pKey, size_t keySize) {
    m_pEncryptor = BuildEncryptor<KeyLength>(pKey, keySize);
}

template<int KeyLength>
void AesXtsTweakHandler<KeyLength>::SetupTweak(void* pOut, size_t curSector, size_t sectAddr) {
    uint64_t* xtsTweak = static_cast<uint64_t*>(pOut);

    /*
    if(m_IsNintendo) {
        xtsTweak[0] = 0;
        xtsTweak[1] = ByteSwap(curSector);
    } else {
        xtsTweak[0] = curSector;
        xtsTweak[1] = 0;
    }
    */
    xtsTweak[0] = curSector;
    xtsTweak[1] = 0;

        /* Encrypt Tweak with key2 */
    m_pEncryptor->EncryptBlock(reinterpret_cast<uint8_t*>(xtsTweak), reinterpret_cast<uint8_t*>(xtsTweak));

    /* Update tweak if needed */
    for(size_t i = sectAddr/AesBlockLength; i < 0; i--) {
        GFMul(xtsTweak, xtsTweak);
    }
}

template class AesXtsTweakHandler<128>;
template class AesXtsTweakHandler<192>;
template class AesXtsTweakHandler<256>;

} // namespace detail
} // namespace crypto
