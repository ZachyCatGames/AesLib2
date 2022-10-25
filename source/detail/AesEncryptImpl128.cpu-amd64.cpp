#include <AesLib/detail/AesEncryptImpl128.cpu-amd64.h>

namespace crypto {
namespace detail {

AesEncryptImpl128::AesEncryptImpl128() = default;

AesEncryptImpl128::AesEncryptImpl128(const void* pKey, size_t keySize) {
    this->Initialize(pKey, keySize);
}

AesEncryptImpl128::~AesEncryptImpl128() = default;

void AesEncryptImpl128::Initialize(const void* pKey, size_t keySize) {
    std::memcpy(&m_RoundKeys[0], pKey, 0x10);
    this->ExpandKeyImpl();
}

void AesEncryptImpl128::Finalize() {
    /* ... */
}

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

__m128i aes_128_key_expansion(__m128i key, __m128i keygened){
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

void AesEncryptImpl128::ExpandKeyImpl() { 
    m_RoundKeys[1]  = AES_128_key_exp(m_RoundKeys[0], 0x01);
    m_RoundKeys[2]  = AES_128_key_exp(m_RoundKeys[1], 0x02);
    m_RoundKeys[3]  = AES_128_key_exp(m_RoundKeys[2], 0x04);
    m_RoundKeys[4]  = AES_128_key_exp(m_RoundKeys[3], 0x08);
    m_RoundKeys[5]  = AES_128_key_exp(m_RoundKeys[4], 0x10);
    m_RoundKeys[6]  = AES_128_key_exp(m_RoundKeys[5], 0x20);
    m_RoundKeys[7]  = AES_128_key_exp(m_RoundKeys[6], 0x40);
    m_RoundKeys[8]  = AES_128_key_exp(m_RoundKeys[7], 0x80);
    m_RoundKeys[9]  = AES_128_key_exp(m_RoundKeys[8], 0x1B);
    m_RoundKeys[10] = AES_128_key_exp(m_RoundKeys[9], 0x36);
}

void AesEncryptImpl128::EncryptBlock(void* pOut, const void* pIn) {
    constexpr const uint8_t roundCount = 9;

    /* Add first roundkey */
    __m128i block = _mm_xor_si128(*static_cast<const __m128i*>(pIn), m_RoundKeys[0]);

    /* Add roundkeys */
    for(uint8_t round = 1; round <= roundCount; round++) {
        block = _mm_aesenc_si128(block, m_RoundKeys[round]);
    }

    /* Add last roundkey */
    *static_cast<__m128i*>(pOut) = _mm_aesenclast_si128(block, m_RoundKeys[10]);
}

} // namespace detail
} // namespace crypto
