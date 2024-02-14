#include <AesLib/AesXtsEncryptor.h>
#include <AesLib/detail/AesGFMul.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength, typename TweakHandler>
AesXtsEncryptor<KeyLength, TweakHandler>::AesXtsEncryptor() :
    m_pEncryptor(detail::BuildEncryptor<KeyLength>())
{
    /* ... */
}

template<int KeyLength, typename TweakHandler>
AesXtsEncryptor<KeyLength, TweakHandler>::AesXtsEncryptor(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize) :
    m_pEncryptor(detail::BuildEncryptor<KeyLength>(pKey1, key1Size)),
    m_TweakHandler(pKey2, key2Size),
    m_SectorSize(sectSize)
{
    /* ... */
}

template<int KeyLength, typename TweakHandler>
AesXtsEncryptor<KeyLength, TweakHandler>::~AesXtsEncryptor() = default;

template<int KeyLength, typename TweakHandler>
void AesXtsEncryptor<KeyLength, TweakHandler>::Initialize(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize) {
    m_pEncryptor->Initialize(pKey1, key1Size);
    m_TweakHandler.Initialize(pKey2, key2Size);
    m_SectorSize = sectSize;
}

template<int KeyLength, typename TweakHandler>
void AesXtsEncryptor<KeyLength, TweakHandler>::Finalize() {
    m_pEncryptor->Finalize();
}

template<int KeyLength, typename TweakHandler>
AesResult AesXtsEncryptor<KeyLength, TweakHandler>::EncryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize, ptrdiff_t addr) {
    uint8_t* pOut8 = static_cast<uint8_t*>(pOut);
    const uint8_t* pIn8 = static_cast<const uint8_t*>(pIn);
    uint8_t xtsTweak[Aes128BlockLength];
    uint8_t tmp[Aes128BlockLength];
    size_t pos = 0;
    size_t currentSector = addr/m_SectorSize;
    size_t sectorAddress = addr - (currentSector * m_SectorSize);

    /* Assert that data is aligned to 0x10 bytes */
    if(inSize % Aes128BlockLength != 0) {
        return AesResult::NotAligned;
    }

    /* Setup tweak */
    m_TweakHandler.SetupTweak(xtsTweak, currentSector, sectorAddress);

    while(pos < inSize) {
        /* XOR Encrypted Tweak with Input */
        detail::AesXorBlock128(tmp, xtsTweak, pIn8 + pos);

        /* Encrypt Data with key1 */
        m_pEncryptor->EncryptBlock(tmp, tmp);

        /* XOR Tweak with output */
        detail::AesXorBlock128(pOut8 + pos, tmp, xtsTweak);

        /* Multiply tweak */
        detail::GFMul(xtsTweak, xtsTweak);

        /* Update position and sector address */
        pos           += Aes128BlockLength;
        sectorAddress += Aes128BlockLength;

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

template class AesXtsEncryptor<128, detail::AesXtsTweakHandler<128>>;
template class AesXtsEncryptor<192, detail::AesXtsTweakHandler<192>>;
template class AesXtsEncryptor<256, detail::AesXtsTweakHandler<256>>;

template class AesXtsEncryptor<128, detail::AesXtsNTweakHandler<128>>;
template class AesXtsEncryptor<192, detail::AesXtsNTweakHandler<192>>;
template class AesXtsEncryptor<256, detail::AesXtsNTweakHandler<256>>;

} // namespace crypto