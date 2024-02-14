#include <AesLib/detail/AesEcbEncryptorImpl.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {
namespace detail {

AesEcbEncryptorImpl::AesEcbEncryptorImpl(UniqueEncryptor&& pEnc) :
    m_pImpl(std::move(pEnc)) {}

AesEcbEncryptorImpl::~AesEcbEncryptorImpl() = default;

void AesEcbEncryptorImpl::Initialize(const void* pKey, size_t keySize) {
    m_pImpl->Initialize(pKey, keySize);
}

void AesEcbEncryptorImpl::Finalize() {
    /* ... */
}

AesResult AesEcbEncryptorImpl::EncryptBlock(void* pOut, const void* pIn) {
    m_pImpl->EncryptBlock(static_cast<uint8_t*>(pOut), static_cast<const uint8_t*>(pIn));

    return AesResult::Success;
}

AesResult AesEcbEncryptorImpl::EncryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize) {
    /* Compare in/out sizes. */
    if(outSize < inSize)
        return AesResult::OutTooSmall;

    /* Check alignment. */
    if(inSize % AesBlockLength)
        return AesResult::NotAligned;

    for(size_t i = 0; i < inSize; i += AesBlockLength) {
        m_pImpl->EncryptBlock(static_cast<uint8_t*>(pOut) + i, static_cast<const uint8_t*>(pIn) + i);
    }

    return AesResult::Success;
}

} // namespace detail
} // namespace crypto
