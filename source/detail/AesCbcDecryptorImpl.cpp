#include <AesLib/detail/AesCbcDecryptorImpl.h>
#include <AesLib/detail/AesXorBlock128.h>

namespace crypto {
namespace detail {

AesCbcDecryptorImpl::AesCbcDecryptorImpl(UniqueDecryptor&& pDec) :
    m_pDecryptor(std::move(pDec))
{
    /* ... */
}

AesCbcDecryptorImpl::AesCbcDecryptorImpl(UniqueDecryptor&& pDec, const void* pIv, size_t ivSize) :
    m_pDecryptor(std::move(pDec))
{
    std::memcpy(m_Iv, pIv, AesBlockLength);
}

AesCbcDecryptorImpl::~AesCbcDecryptorImpl() = default;

void AesCbcDecryptorImpl::Initialize(const void* pKey, size_t keySize, const void* pIv, size_t ivSize) {
    /* Initialize ECB encrypter. */
    m_pDecryptor->Initialize(pKey, keySize);

    /* Copy iv. */
    std::memcpy(m_Iv, pIv, AesBlockLength);
}

void AesCbcDecryptorImpl::Finalize() {
    /* Finalize ECB encrypter. */
    m_pDecryptor->Finalize();
}

AesResult AesCbcDecryptorImpl::DecryptData(void* pOut, size_t outSize, const void* pIn, size_t size) {
    uint8_t tmp[AesBlockLength];
    uint8_t nextIv[AesBlockLength];

    /* Assert that data is aligned to 0x10 bytes */
    if(size % AesBlockLength != 0) {
        return AesResult::NotAligned;
    }

    /* Loop until all data is decrypted */
    for(size_t pos = 0; pos < size; pos += AesBlockLength) {
        /* Copy encrypted data to next iv */
        std::memcpy(nextIv, static_cast<const uint8_t*>(pIn) + pos, AesBlockLength);

        /* Decrypt data with key */
        m_pDecryptor->DecryptBlock(tmp, static_cast<const uint8_t*>(pIn) + pos);

        /* XOR data with iv */
        detail::AesXorBlock128(static_cast<uint8_t*>(pOut) + pos, tmp, m_Iv);

        /* Copy next iv to iv */
        std::memcpy(m_Iv, nextIv, AesBlockLength);
    }

    /* Return */
    return AesResult::Success;
}

} // namespace detail
} // namespace crypto
