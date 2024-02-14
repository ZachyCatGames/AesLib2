#include <AesLib/detail/AesEcbDecryptorImpl.h>
#include <AesLib/detail/AesImplBuilder.h>

namespace crypto {
namespace detail {

AesEcbDecryptorImpl::AesEcbDecryptorImpl(UniqueDecryptor&& pDec) :
    m_pImpl(std::move(pDec)) {}

AesEcbDecryptorImpl::~AesEcbDecryptorImpl() = default;

void AesEcbDecryptorImpl::Initialize(const void* pKey, size_t keySize) {
    m_pImpl->Initialize(pKey, keySize);
}

void AesEcbDecryptorImpl::Finalize() {
    /* ... */
}

AesResult AesEcbDecryptorImpl::DecryptBlock(void* pOut, const void* pIn) {
    m_pImpl->DecryptBlock(static_cast<uint8_t*>(pOut), static_cast<const uint8_t*>(pIn));

    return AesResult::Success;
}

AesResult AesEcbDecryptorImpl::DecryptData(void* pOut, size_t outSize, const void* pIn, size_t inSize) {
    /* Compare in/out sizes. */
    if(outSize < inSize)
        return AesResult::OutTooSmall;

    /* Check alignment. */
    if(inSize % AesBlockLength)
        return AesResult::NotAligned;

    for(size_t i = 0; i < inSize; i += AesBlockLength) {
        m_pImpl->DecryptBlock(static_cast<uint8_t*>(pOut) + i, static_cast<const uint8_t*>(pIn) + i);
    }

    return AesResult::Success;
}

} // namespace detail
} // namespace crypto
