#include <AesLib/detail/arch/amd64/AesDecryptImpl128.cpu-amd64.h>
#include <AesLib/detail/arch/amd64/AesSimdKeyExpansion.cpu-amd64.h>

namespace crypto {
namespace detail {
namespace arch {
namespace amd64 {

AesDecryptImpl128::AesDecryptImpl128() = default;

AesDecryptImpl128::AesDecryptImpl128(const void* pKey, size_t keySize) {
    this->Initialize(pKey, keySize);
}

AesDecryptImpl128::~AesDecryptImpl128() = default;

void AesDecryptImpl128::Initialize(const void* pKey, size_t keySize) {
    this->ExpandKeyImpl(pKey);
}

void AesDecryptImpl128::Finalize() {
    /* ... */
}

void AesDecryptImpl128::ExpandKeyImpl(const void* pKey) { 
    ALIGN(16) __m128i roundKey;
    ALIGN(16) __m128i invKey;

    /* Generate keys. */
    roundKey  = _mm_loadu_si128(static_cast<const __m128i*>(pKey));
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[0]), invKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[11]), roundKey);
    roundKey = AES_128_key_exp(roundKey, 0x01);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[1]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x02);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[2]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x04);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[3]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x08);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[4]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x10);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[5]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x20);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[6]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x40);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[7]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x80);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[8]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x1B);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[9]), invKey);
    roundKey = AES_128_key_exp(roundKey, 0x36);
    invKey   = _mm_aesimc_si128(roundKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[10]), invKey);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[12]), roundKey);
}

void AesDecryptImpl128::DecryptBlock(void* pOut, const void* pIn) {
    constexpr const uint8_t roundCount = 9;
    ALIGN(16) __m128i roundKey;
    ALIGN(16) __m128i block;

    /* Load data. */
    block = _mm_loadu_si128(static_cast<const __m128i*>(pIn));

    /* Subtract first key. */
    roundKey = _mm_loadu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[12]));
    block = _mm_xor_si128(block, roundKey);

    /* Subtract round keys */
    for(uint8_t round = roundCount; round > 0; round--) {
        roundKey = _mm_loadu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[round]));
        block = _mm_aesdec_si128(block, roundKey);
    }

    /* Subtract last round key */
    roundKey = _mm_loadu_si128(reinterpret_cast<__m128i*>(m_InvRoundKeyStorage[11]));
    block = _mm_aesdeclast_si128(block, roundKey);

    /* Save decrypted data. */
    _mm_storeu_si128(static_cast<__m128i*>(pOut), block);
}

} // namespace amd64
} // namespace arch
} // namespace detail
} // namespace crypto
