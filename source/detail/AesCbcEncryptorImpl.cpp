#include <AesLib/detail/AesCbcEncryptorImpl.h>
#include <AesLib/detail/AesXorBlock128.h>
#include <AesLib/detail/AesImplBuilder.h>
#include <cassert>

namespace crypto {
namespace detail {

AesCbcEncryptorImpl::AesCbcEncryptorImpl(UniqueEncryptor&& pEnc) :
    m_pEncryptor(std::move(pEnc)) {}

AesCbcEncryptorImpl::AesCbcEncryptorImpl(UniqueEncryptor&& pEnc, const void* pIv, size_t ivSize) :
    m_pEncryptor(std::move(pEnc))
{
    std::memcpy(m_Iv, pIv, AesBlockLength);
}

AesCbcEncryptorImpl::~AesCbcEncryptorImpl() = default;

void AesCbcEncryptorImpl::Initialize(const void* pKey, size_t keySize, const void* pIv, size_t ivSize) {
    /* Initialize ECB encrypter. */
    m_pEncryptor->Initialize(pKey, keySize);

    /* Copy iv. */
    std::memcpy(m_Iv, pIv, AesBlockLength);
}

void AesCbcEncryptorImpl::Finalize() {
    /* Finalize ECB encrypter. */
    m_pEncryptor->Finalize();
}

AesResult AesCbcEncryptorImpl::EncryptData(void* pOut, size_t outSize, const void* pIn, size_t size) {
    uint8_t tmp[AesBlockLength];

    /* Assert that data is aligned to 0x10 bytes */
    if(size % AesBlockLength != 0) {
        return AesResult::NotAligned;
    }

    /* Loop until all data is encrypted */
    for(size_t pos = 0; pos < size; pos += AesBlockLength) {
        /* Copy input at current position */
        std::memcpy(tmp, static_cast<const uint8_t*>(pIn) + pos, AesBlockLength);

        /* XOR Input with IV */
        detail::AesXorBlock128(tmp, tmp, m_Iv);

        /* Encrypt data with key */
        m_pEncryptor->EncryptBlock(static_cast<uint8_t*>(pOut) + pos, tmp);

        /* Copy encrypted data to iv_buf */
        std::memcpy(m_Iv, static_cast<uint8_t*>(pOut) + pos, AesBlockLength);
    }

    /* Return */
    return AesResult::Success;
}

} // namespace detail
} // namespace crypto
