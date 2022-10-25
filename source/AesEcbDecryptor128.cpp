#include <AesLib/AesEcbDecryptor128.h>
#include <AesLib/AesLookupTables.h>

namespace crypto {

AesEcbDecryptor128::AesEcbDecryptor128() = default;

AesEcbDecryptor128::AesEcbDecryptor128(const void* pKey, size_t keySize) :
    m_Impl(pKey, keySize)
{
    /* ... */
}

AesEcbDecryptor128::~AesEcbDecryptor128() = default;

void AesEcbDecryptor128::Initialize(const void* pKey, size_t keySize) {
    m_Impl.Initialize(pKey, keySize);
}

void AesEcbDecryptor128::Finalize() {
    /* ... */
}

crypto::AesResult AesEcbDecryptor128::DecryptBlock(void* pOut, const void* pIn) {
    m_Impl.DecryptBlock(static_cast<uint8_t*>(pOut), static_cast<const uint8_t*>(pIn));

    return crypto::AesResult::Success;
}

crypto::AesResult AesEcbDecryptor128::DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize) {
    /* Compare in/out sizes. */
    if(outSize < inSize)
        return crypto::AesResult::OutTooSmall;

    /* Check alignment. */
    if(inSize % 0x10)
        return crypto::AesResult::NotAligned;

    size_t blockCount = inSize / 0x10;
    for(size_t i = 0; i < blockCount; ++i) {
        m_Impl.DecryptBlock(static_cast<uint8_t*>(pOut) + i * 0x10, static_cast<const uint8_t*>(pIn) + i * 0x10);
    }

    return crypto::AesResult::Success;
}

} // namespace crypto
