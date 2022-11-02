#include <AesLib/AesEcbEncryptor128.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {

AesEcbEncryptor128::AesEcbEncryptor128() :
    m_pImpl(crypto::detail::BuildEncryptor())
{
    /* ... */
}

AesEcbEncryptor128::AesEcbEncryptor128(const void* pKey, size_t keySize) :
    m_pImpl(crypto::detail::BuildEncryptor(pKey, keySize))
{
    /* ... */
}

AesEcbEncryptor128::~AesEcbEncryptor128() = default;

void AesEcbEncryptor128::Initialize(const void* pKey, size_t keySize) {
    m_pImpl->Initialize(pKey, keySize);
}

void AesEcbEncryptor128::Finalize() {
    /* ... */
}

crypto::AesResult AesEcbEncryptor128::EncryptBlock(void* pOut, const void* pIn) {
    m_pImpl->EncryptBlock(static_cast<uint8_t*>(pOut), static_cast<const uint8_t*>(pIn));

    return crypto::AesResult::Success;
}

crypto::AesResult AesEcbEncryptor128::EncryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize) {
    /* Compare in/out sizes. */
    if(outSize < inSize)
        return crypto::AesResult::OutTooSmall;

    /* Check alignment. */
    if(inSize % 0x10)
        return crypto::AesResult::NotAligned;

    size_t blockCount = inSize / 0x10;
    for(size_t i = 0; i < blockCount; ++i) {
        m_pImpl->EncryptBlock(static_cast<uint8_t*>(pOut) + i * 0x10, static_cast<const uint8_t*>(pIn) + i * 0x10);
    }

    return crypto::AesResult::Success;
}

} // namespace crypto
