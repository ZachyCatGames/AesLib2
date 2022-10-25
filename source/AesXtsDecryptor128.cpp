#include <AesLib/AesXtsDecryptor128.h>
#include <AesLib/detail/AesGFMul.h>
#include <AesLib/detail/AesXorBlock128.h>

namespace crypto {

AesXtsDecryptor128::AesXtsDecryptor128() = default;

AesXtsDecryptor128::AesXtsDecryptor128(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize) :
    m_Decryptor(pKey1, key1Size),
    m_TweakHandler(pKey2, key2Size),
    m_SectorSize(sectSize)
{
    /* ... */
}

AesXtsDecryptor128::~AesXtsDecryptor128() = default;

void AesXtsDecryptor128::Initialize(const void* pKey1, size_t key1Size, const void* pKey2, size_t key2Size, size_t sectSize) {
    m_Decryptor.Initialize(pKey1, key1Size);
    m_TweakHandler.Initialize(pKey2, key2Size);
    m_SectorSize = sectSize;
}

void AesXtsDecryptor128::Finalize() {
    m_Decryptor.Finalize();
}

crypto::AesResult AesXtsDecryptor128::DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize, ptrdiff_t addr) {
    uint8_t* pOutData = static_cast<uint8_t*>(pOut);
    const uint8_t* pInData = static_cast<const uint8_t*>(pIn);
    uint8_t xtsTweak[Aes128BlockLength];
    uint8_t tmp[Aes128BlockLength];
    size_t pos = 0;
    size_t currentSector = addr/m_SectorSize;
    size_t sectorAddress = addr - (currentSector * m_SectorSize);

    /* Assert that data is aligned */
    if(inSize % Aes128BlockLength)
        return crypto::AesResult::NotAligned;

    /* Setup tweak */
    m_TweakHandler.SetupTweak(xtsTweak, currentSector, sectorAddress);

    while(pos < inSize) {
        /* XOR Encrypted Tweak with Input */
        crypto::detail::AesXorBlock128(tmp, xtsTweak, pInData + pos);

        /* Encrypt Data with key1 */
        m_Decryptor.DecryptBlock(tmp, tmp);

        /* XOR Tweak with output */
        crypto::detail::AesXorBlock128(pOutData + pos, tmp, xtsTweak);

        /* Multiply tweak */
        crypto::detail::GFMul(xtsTweak, xtsTweak);

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
    return crypto::AesResult::Success;
}

} // namespace crypto
