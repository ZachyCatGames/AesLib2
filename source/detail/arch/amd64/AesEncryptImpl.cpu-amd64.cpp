#include <AesLib/detail/arch/amd64/AesEncryptImpl.cpu-amd64.h>
#include <AesLib/detail/arch/amd64/AesSimdKeyExpansion.cpu-amd64.h>
#include <AesLib/detail/AesExpandKeyImpl.h>

namespace crypto {
namespace detail {
namespace arch {
namespace amd64 {

template<int KeyLength>
AesEncryptImpl<KeyLength>::AesEncryptImpl() = default;

template<int KeyLength>
AesEncryptImpl<KeyLength>::AesEncryptImpl(const void* pKey, size_t keySize) {
    this->Initialize(pKey, keySize);
}

template<int KeyLength>
AesEncryptImpl<KeyLength>::~AesEncryptImpl() = default;

template<int KeyLength>
void AesEncryptImpl<KeyLength>::Initialize(const void* pKey, size_t keySize) {
    this->ExpandKeyImpl(pKey);
}

template<int KeyLength>
void AesEncryptImpl<KeyLength>::Finalize() {
    /* ... */
}

template<int KeyLength>
void AesEncryptImpl<KeyLength>::ExpandKeyImpl(const void* pKey) { 
    ALIGN(16) __m128i roundKey;

    // TODO: Properly deal with AES192/AES256 keygen.
    if constexpr(KeyLength >= 192) {
        std::memcpy(m_RoundKeyStorage, pKey, KeySize);
        crypto::detail::AesExpandKeyImpl<KeyLength>(m_RoundKeyStorage);
        return;
    }

    /* Generate keys. */
    roundKey  = _mm_loadu_si128(static_cast<const __m128i*>(pKey));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[0]), roundKey);
    roundKey = AES_128_key_exp(roundKey, 0x01);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[1]), roundKey);
    roundKey = AES_128_key_exp(roundKey, 0x02);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[2]), roundKey);
    roundKey = AES_128_key_exp(roundKey, 0x04);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[3]), roundKey);
    roundKey = AES_128_key_exp(roundKey, 0x08);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[4]), roundKey);
    roundKey = AES_128_key_exp(roundKey, 0x10);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[5]), roundKey);
    roundKey = AES_128_key_exp(roundKey, 0x20);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[6]), roundKey);
    roundKey = AES_128_key_exp(roundKey, 0x40);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[7]), roundKey);
    roundKey = AES_128_key_exp(roundKey, 0x80);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[8]), roundKey);
    roundKey = AES_128_key_exp(roundKey, 0x1B);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[9]), roundKey);
    roundKey = AES_128_key_exp(roundKey, 0x36);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[10]), roundKey);
}

template<int KeyLength>
void AesEncryptImpl<KeyLength>::EncryptBlock(void* pOut, const void* pIn) {
    constexpr uint8_t roundCount = 9;
    ALIGN(16) __m128i roundKey;
    ALIGN(16) __m128i block;

    /* Load data. */
    block = _mm_loadu_si128(static_cast<const __m128i*>(pIn));

    /* Add first roundkey */
    roundKey = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_RoundKeyStorage[0]));
    block = _mm_xor_si128(block, roundKey);

    /* Add roundkeys */
    for(uint8_t round = 1; round <= m_Rounds - 2; round++) {
        roundKey = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_RoundKeyStorage[round]));
        block = _mm_aesenc_si128(block, roundKey);
    }

    /* Add last roundkey */
    roundKey = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_RoundKeyStorage[m_Rounds - 1]));
    block = _mm_aesenclast_si128(block, roundKey);

    /* Save encrypted data. */
    _mm_storeu_si128(static_cast<__m128i*>(pOut), block);
}

template class AesEncryptImpl<128>;
template class AesEncryptImpl<192>;
template class AesEncryptImpl<256>;

} // namespace amd64
} // namespace arch
} // namespace detail
} // namespace crypto
