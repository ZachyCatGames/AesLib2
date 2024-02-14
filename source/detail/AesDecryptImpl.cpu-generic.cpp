#include <AesLib/detail/AesDecryptImpl.cpu-generic.h>
#include <AesLib/detail/AesExpandKeyImpl.h>
#include <AesLib/detail/AesLookupTables.h>
#include <AesLib/detail/AesByteSwap.h>

namespace crypto {
namespace detail {

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
    std::memcpy(m_RoundKeys, pKey, KeySize);
    AesExpandKeyImpl<KeyLength>(m_RoundKeys);

    /* Inverse keys. */
    for(int i = 4; i < m_KeyWordCount - 4; ++i) {
        m_RoundKeys[i] = T_TableInv0[sbox[m_RoundKeys[i] & 0xFF]] ^
                         T_TableInv1[sbox[m_RoundKeys[i] >> 8 & 0xFF]] ^
                         T_TableInv2[sbox[m_RoundKeys[i] >> 16 & 0xFF]] ^
                         T_TableInv3[sbox[m_RoundKeys[i] >> 24 & 0xFF]];
    }
}

template<int KeyLength>
void AesDecryptImpl<KeyLength>::Finalize() {
    /* ... */
}

template<int KeyLength>
void AesDecryptImpl<KeyLength>::DecryptBlock(void* pOut, const void* pIn) {
    const uint32_t* pIn32 = static_cast<const uint32_t*>(pIn);
    uint32_t* pOut32 = static_cast<uint32_t*>(pOut);
    uint32_t tmp[4];

    /* Subtract Last Roundkey */
    for(uint8_t i = 0; i < 4; i++) {
        tmp[i] = pIn32[i] ^ m_RoundKeys[(m_Rounds - 1) * 4 + i];
    }

    for(uint8_t round = m_Rounds - 2; round > 0; round--) {
        pOut32[0] = T_TableInv0[tmp[0] & 0xFF] ^ T_TableInv1[tmp[3] >> 8 & 0xFF] ^ T_TableInv2[tmp[2] >> 16 & 0xFF] ^ T_TableInv3[tmp[1] >> 24] ^ m_RoundKeys[round * 4 + 0];
        pOut32[1] = T_TableInv0[tmp[1] & 0xFF] ^ T_TableInv1[tmp[0] >> 8 & 0xFF] ^ T_TableInv2[tmp[3] >> 16 & 0xFF] ^ T_TableInv3[tmp[2] >> 24] ^ m_RoundKeys[round * 4 + 1];
        pOut32[2] = T_TableInv0[tmp[2] & 0xFF] ^ T_TableInv1[tmp[1] >> 8 & 0xFF] ^ T_TableInv2[tmp[0] >> 16 & 0xFF] ^ T_TableInv3[tmp[3] >> 24] ^ m_RoundKeys[round * 4 + 2];
        pOut32[3] = T_TableInv0[tmp[3] & 0xFF] ^ T_TableInv1[tmp[2] >> 8 & 0xFF] ^ T_TableInv2[tmp[1] >> 16 & 0xFF] ^ T_TableInv3[tmp[0] >> 24] ^ m_RoundKeys[round * 4 + 3];
        std::memcpy(tmp, pOut, AesBlockLength);
    }

    tmp[0] = inv_s[pOut32[0] & 0xFF] |
             inv_s[pOut32[3] >> 8 & 0xFF] << 8 |
             inv_s[pOut32[2] >> 16 & 0xFF] << 16 |
             inv_s[pOut32[1] >> 24 & 0xFF] << 24;
    tmp[1] = inv_s[pOut32[1] & 0xFF] |
             inv_s[pOut32[0] >> 8 & 0xFF] << 8 |
             inv_s[pOut32[3] >> 16 & 0xFF] << 16 |
             inv_s[pOut32[2] >> 24 & 0xFF] << 24;
    tmp[2] = inv_s[pOut32[2] & 0xFF] |
             inv_s[pOut32[1] >> 8 & 0xFF] << 8 |
             inv_s[pOut32[0] >> 16 & 0xFF] << 16 |
             inv_s[pOut32[3] >> 24 & 0xFF] << 24;
    tmp[3] = inv_s[pOut32[3] & 0xFF] |
             inv_s[pOut32[2] >> 8 & 0xFF] << 8 |
             inv_s[pOut32[1] >> 16 & 0xFF] << 16 |
             inv_s[pOut32[0] >> 24 & 0xFF] << 24;

    /* Substract First Roundkey */
    for(uint8_t i = 0; i < 4; i++) {
        pOut32[i] = tmp[i] ^ m_RoundKeys[i];
    }
}

template class AesDecryptImpl<128>;
template class AesDecryptImpl<192>;
template class AesDecryptImpl<256>;

} // namespace detail
} // namespace crypto
