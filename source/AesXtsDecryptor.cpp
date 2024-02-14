#include <AesLib/AesXtsDecryptor.h>
#include <AesLib/detail/AesGFMul.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength, typename TweakHandler>
AesXtsDecryptor<KeyLength, TweakHandler>::AesXtsDecryptor() :
    m_pDecryptor(detail::BuildDecryptor<KeyLength>())
{
    /* ... */
}

template<int KeyLength, typename TweakHandler>
AesXtsDecryptor<KeyLength, TweakHandler>::AesXtsDecryptor(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize) :
    m_pDecryptor(detail::BuildDecryptor<KeyLength>(pKey1, key1Size)),
    m_TweakHandler(pKey2, key2Size),
    m_SectorSize(sectSize)
{
    /* ... */
}

template<int KeyLength, typename TweakHandler>
AesXtsDecryptor<KeyLength, TweakHandler>::~AesXtsDecryptor() = default;

template<int KeyLength, typename TweakHandler>
void AesXtsDecryptor<KeyLength, TweakHandler>::Initialize(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize) {
    m_pDecryptor->Initialize(pKey1, key1Size);
    m_TweakHandler.Initialize(pKey2, key2Size);
    m_SectorSize = sectSize;
}

template<int KeyLength, typename TweakHandler>
void AesXtsDecryptor<KeyLength, TweakHandler>::Finalize() {
    m_pDecryptor->Finalize();
}

template<int KeyLength, typename TweakHandler>
AesResult AesXtsDecryptor<KeyLength, TweakHandler>::DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize, ptrdiff_t addr) {
    uint8_t* pOut8 = static_cast<uint8_t*>(pOut);
    const uint8_t* pIn8 = static_cast<const uint8_t*>(pIn);
    uint8_t xtsTweak[AesBlockLength];
    uint8_t tmp[AesBlockLength];
    size_t pos = 0;
    size_t currentSector = addr/m_SectorSize;
    size_t sectorAddress = addr - (currentSector * m_SectorSize);

    /* Assert that data is aligned */
    if(inSize % AesBlockLength)
        return AesResult::NotAligned;

    /* Setup tweak */
    m_TweakHandler.SetupTweak(xtsTweak, currentSector, sectorAddress);

    while(pos < inSize) {
        /* XOR Encrypted Tweak with Input */
        detail::AesXorBlock128(tmp, xtsTweak, pIn8 + pos);

        /* Encrypt Data with key1 */
        m_pDecryptor->DecryptBlock(tmp, tmp);

        /* XOR Tweak with output */
        detail::AesXorBlock128(pOut8 + pos, tmp, xtsTweak);

        /* Multiply tweak */
        detail::GFMul(xtsTweak, xtsTweak);

        /* Update position and sector address */
        pos           += AesBlockLength;
        sectorAddress += AesBlockLength;

        /* Reset tweak if needed */
        if(sectorAddress >= m_SectorSize) {
            currentSector++;
            sectorAddress = 0;
            m_TweakHandler.SetupTweak(xtsTweak, currentSector, sectorAddress);
        }
    }

    /* Return */
    return AesResult::Success;
}

template class AesXtsDecryptor<128, detail::AesXtsTweakHandler<128>>;
template class AesXtsDecryptor<192, detail::AesXtsTweakHandler<192>>;
template class AesXtsDecryptor<256, detail::AesXtsTweakHandler<256>>;

template class AesXtsDecryptor<128, detail::AesXtsNTweakHandler<128>>;
template class AesXtsDecryptor<192, detail::AesXtsNTweakHandler<192>>;
template class AesXtsDecryptor<256, detail::AesXtsNTweakHandler<256>>;

} // namespace crypto
