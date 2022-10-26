#include <AesLib/detail/AesEncryptImpl128.cpu-amd64.h>
#include <AesLib/detail/AesSimdKeyExpansion.cpu-amd64.h>

namespace crypto {
namespace detail {

AesEncryptImpl128::AesEncryptImpl128() = default;

AesEncryptImpl128::AesEncryptImpl128(const void* pKey, size_t keySize) {
    this->Initialize(pKey, keySize);
}

AesEncryptImpl128::~AesEncryptImpl128() = default;

void AesEncryptImpl128::Initialize(const void* pKey, size_t keySize) {
    this->ExpandKeyImpl(pKey);
}

void AesEncryptImpl128::Finalize() {
    /* ... */
}

void AesEncryptImpl128::ExpandKeyImpl(const void* pKey) { 
    ALIGN(16) __m128i roundKey;

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

void AesEncryptImpl128::EncryptBlock(void* pOut, const void* pIn) {
    constexpr uint8_t roundCount = 9;
    ALIGN(16) __m128i roundKey;
    ALIGN(16) __m128i block;

    /* Load data. */
    block = _mm_loadu_si128(static_cast<const __m128i*>(pIn));

    /* Add first roundkey */
    roundKey = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_RoundKeyStorage[0]));
    block = _mm_xor_si128(block, roundKey);

    /* Add roundkeys */
    for(uint8_t round = 1; round <= roundCount; round++) {
        roundKey = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_RoundKeyStorage[round]));
        block = _mm_aesenc_si128(block, roundKey);
    }

    /* Add last roundkey */
    roundKey = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_RoundKeyStorage[10]));
    block = _mm_aesenclast_si128(block, roundKey);

    /* Save encrypted data. */
    _mm_storeu_si128(static_cast<__m128i*>(pOut), block);
}

} // namespace detail
} // namespace crypto
