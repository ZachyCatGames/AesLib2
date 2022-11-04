#include <AesLib/AesXtsDecryptor.h>
#include <AesLib/detail/AesGFMul.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

template<int KeyLength>
AesXtsDecryptor<KeyLength>::AesXtsDecryptor() :
    m_pDecryptor(crypto::detail::BuildDecryptor<KeyLength>())
{
    /* ... */
}

template<int KeyLength>
AesXtsDecryptor<KeyLength>::AesXtsDecryptor(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize) :
    m_pDecryptor(crypto::detail::BuildDecryptor<KeyLength>(pKey1, key1Size)),
    m_TweakHandler(pKey2, key2Size),
    m_SectorSize(sectSize)
{
    /* ... */
}

template<int KeyLength>
AesXtsDecryptor<KeyLength>::~AesXtsDecryptor() = default;

template<int KeyLength>
void AesXtsDecryptor<KeyLength>::Initialize(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize) {
    m_pDecryptor->Initialize(pKey1, key1Size);
    m_TweakHandler.Initialize(pKey2, key2Size);
    m_SectorSize = sectSize;
}

template<int KeyLength>
void AesXtsDecryptor<KeyLength>::Finalize() {
    m_pDecryptor->Finalize();
}

template<int KeyLength>
crypto::AesResult AesXtsDecryptor<KeyLength>::DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize, ptrdiff_t addr) {
    uint8_t* pOut8 = static_cast<uint8_t*>(pOut);
    const uint8_t* pIn8 = static_cast<const uint8_t*>(pIn);
    uint8_t xtsTweak[crypto::AesBlockLength];
    uint8_t tmp[crypto::AesBlockLength];
    size_t pos = 0;
    size_t currentSector = addr/m_SectorSize;
    size_t sectorAddress = addr - (currentSector * m_SectorSize);

    /* Assert that data is aligned */
    if(inSize % crypto::AesBlockLength)
        return crypto::AesResult::NotAligned;

    /* Setup tweak */
    m_TweakHandler.SetupTweak(xtsTweak, currentSector, sectorAddress);

    while(pos < inSize) {
        /* XOR Encrypted Tweak with Input */
        crypto::detail::AesXorBlock128(tmp, xtsTweak, pIn8 + pos);

        /* Encrypt Data with key1 */
        m_pDecryptor->DecryptBlock(tmp, tmp);

        /* XOR Tweak with output */
        crypto::detail::AesXorBlock128(pOut8 + pos, tmp, xtsTweak);

        /* Multiply tweak */
        crypto::detail::GFMul(xtsTweak, xtsTweak);

        /* Update position and sector address */
        pos           += crypto::AesBlockLength;
        sectorAddress += crypto::AesBlockLength;

        /* Reset tweak if needed */
        if(sectorAddress >= m_SectorSize) {
            currentSector++;
            sectorAddress = 0;
            m_TweakHandler.SetupTweak(xtsTweak, currentSector, sectorAddress);
        }
    }

    /* Return */
    return crypto::AesResult::Success;
}

template class AesXtsDecryptor<128>;
template class AesXtsDecryptor<192>;
template class AesXtsDecryptor<256>;

} // namespace crypto
