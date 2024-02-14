#include <AesLib/detail/AesXtsDecryptorImpl.h>
#include <AesLib/detail/AesGFMul.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {
namespace detail {

template<typename TweakHandler>
AesXtsDecryptorImpl<TweakHandler>::AesXtsDecryptorImpl(UniqueDecryptor&& pEnc1, UniqueEncryptor&& pEnc2) :
    m_pDecryptor(std::move(pEnc1)),
    m_TweakHandler(std::move(pEnc2)) {}

template<typename TweakHandler>
AesXtsDecryptorImpl<TweakHandler>::AesXtsDecryptorImpl(UniqueDecryptor&& pEnc1, UniqueEncryptor&& pEnc2, size_t sectSize) :
    m_pDecryptor(std::move(pEnc1)),
    m_TweakHandler(std::move(pEnc2)),
    m_SectorSize(sectSize) {}

template<typename TweakHandler>
AesXtsDecryptorImpl<TweakHandler>::~AesXtsDecryptorImpl() = default;

template<typename TweakHandler>
void AesXtsDecryptorImpl<TweakHandler>::Initialize(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize) {
    m_pDecryptor->Initialize(pKey1, key1Size);
    m_TweakHandler.Initialize(pKey2, key2Size);
    m_SectorSize = sectSize;
}

template<typename TweakHandler>
void AesXtsDecryptorImpl<TweakHandler>::Finalize() {
    m_pDecryptor->Finalize();
}

template<typename TweakHandler>
AesResult AesXtsDecryptorImpl<TweakHandler>::DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize, ptrdiff_t addr) {
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

template class AesXtsDecryptorImpl<detail::AesXtsTweakHandler>;
template class AesXtsDecryptorImpl<detail::AesXtsNTweakHandler>;

} // namespace detail
} // namespace crypto
