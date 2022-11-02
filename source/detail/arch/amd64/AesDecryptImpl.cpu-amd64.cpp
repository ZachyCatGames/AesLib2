#include <AesLib/detail/arch/amd64/AesDecryptImpl.cpu-amd64.h>
#include <AesLib/detail/arch/amd64/AesSimdKeyExpansion.cpu-amd64.h>
#include <AesLib/detail/AesLookupTables.h>

namespace crypto {
namespace detail {
namespace arch {
namespace amd64 {

template<int KeyLength>
AesDecryptImpl<KeyLength>::AesDecryptImpl() = default;

template<int KeyLength>
AesDecryptImpl<KeyLength>::AesDecryptImpl(const void* pKey, size_t keySize) {
    this->Initialize(pKey, keySize);
}

template<int KeyLength>
AesDecryptImpl<KeyLength>::~AesDecryptImpl() = default;

template<int KeyLength>
void AesDecryptImpl<KeyLength>::Initialize(const void* pKey, size_t keySize) {
    this->ExpandKeyImpl(pKey);
}

template<int KeyLength>
void AesDecryptImpl<KeyLength>::Finalize() {
    /* ... */
}

template<int KeyLength>
void AesDecryptImpl<KeyLength>::ExpandKeyImpl(const void* pKey) { 
    ALIGN(16) __m128i roundKey;
    ALIGN(16) __m128i invKey;

    /* Generate keys. */
    roundKey  = _mm_loadu_si128(static_cast<const __m128i*>(pKey));
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[0]), invKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[11]), roundKey);
    roundKey = AES_128_key_exp(roundKey, 0x01);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[1]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x02);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[2]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x04);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[3]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x08);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[4]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x10);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[5]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x20);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[6]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x40);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[7]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x80);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[8]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x1B);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[9]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x36);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[10]), invKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[12]), roundKey);
}

template<int KeyLength>
void AesDecryptImpl<KeyLength>::DecryptBlock(void* pOut, const void* pIn) {
    ALIGN(16) __m128i roundKey;
    ALIGN(16) __m128i block;

    /* Load data. */
    block = _mm_loadu_si128(static_cast<const __m128i*>(pIn));

    /* Subtract first key. */
    roundKey = _mm_loadu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[12]));
    block = _mm_xor_si128(block, roundKey);

    /* Subtract round keys */
    for(uint8_t round = m_Rounds - 2; round > 0; round--) {
        roundKey = _mm_loadu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[round]));
        block = _mm_aesdec_si128(block, roundKey);
    }

    /* Subtract last round key */
    roundKey = _mm_loadu_si128(reinterpret_cast<__m128i*>(m_RoundKeyStorage[11]));
    block = _mm_aesdeclast_si128(block, roundKey);

    /* Save decrypted data. */
    _mm_storeu_si128(static_cast<__m128i*>(pOut), block);
}

template class AesDecryptImpl<128>;
template class AesDecryptImpl<192>;
template class AesDecryptImpl<256>;

} // namespace amd64
} // namespace arch
} // namespace detail
} // namespace crypto
