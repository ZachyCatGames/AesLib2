#include <AesLib/detail/AesEncryptImpl.cpu-generic.h>
#include <AesLib/detail/AesExpandKeyImpl.h>
#include <AesLib/detail/AesLookupTables.h>
#include <AesLib/detail/AesByteSwap.h>

namespace crypto {
namespace detail {

template<int KeyLength>
AesEncryptImpl<KeyLength>::AesEncryptImpl() = default;

template<int KeyLength>
AesEncryptImpl<KeyLength>::AesEncryptImpl(const void* pKey, size_t keySize) {
    std::memcpy(m_RoundKeys[0], pKey, KeySize);
    crypto::detail::AesExpandKeyImpl<KeyLength>(m_RoundKeys[0]);
}

template<int KeyLength>
AesEncryptImpl<KeyLength>::~AesEncryptImpl() = default;

template<int KeyLength>
void AesEncryptImpl<KeyLength>::Initialize(const void* pKey, size_t keySize) {
    std::memcpy(m_RoundKeys[0], pKey, KeySize);
    crypto::detail::AesExpandKeyImpl<KeyLength>(m_RoundKeys[0]);
}

template<int KeyLength>
void AesEncryptImpl<KeyLength>::Finalize() {
    /* ... */
}

template<int KeyLength>
void AesEncryptImpl<KeyLength>::EncryptBlock(void* pOut, const void* pIn) {
    const uint32_t* pIn32 = static_cast<const uint32_t*>(pIn);
    uint32_t* pOut32 = static_cast<uint32_t*>(pOut);
    uint32_t tmp[4];

    /* Add roundkey */
    for(uint8_t i = 0; i < 4; i++) {
        pOut32[i] = pIn32[i] ^ m_RoundKeys[0][i];
    }

    /* Shift Rows Right, Mix Columns, and Subsitute. */
    for(uint8_t round = 1; round <= m_Rounds - 2; round++) {

        tmp[0] = T_Table0[pOut32[0] & 0xFF] ^ T_Table1[pOut32[1] >> 8 & 0xFF] ^ T_Table2[pOut32[2] >> 16 & 0xFF] ^ T_Table3[pOut32[3] >> 24];
        tmp[1] = T_Table0[pOut32[1] & 0xFF] ^ T_Table1[pOut32[2] >> 8 & 0xFF] ^ T_Table2[pOut32[3] >> 16 & 0xFF] ^ T_Table3[pOut32[0] >> 24];
        tmp[2] = T_Table0[pOut32[2] & 0xFF] ^ T_Table1[pOut32[3] >> 8 & 0xFF] ^ T_Table2[pOut32[0] >> 16 & 0xFF] ^ T_Table3[pOut32[1] >> 24];
        tmp[3] = T_Table0[pOut32[3] & 0xFF] ^ T_Table1[pOut32[0] >> 8 & 0xFF] ^ T_Table2[pOut32[1] >> 16 & 0xFF] ^ T_Table3[pOut32[2] >> 24];

        for(int i = 0; i < 4; ++i) {
            pOut32[i] = tmp[i] ^ m_RoundKeys[round][i];
        }
    }

    /* Shift Rows Right and Subsitute */
    tmp[0] = sbox[(pOut32[0] & 0xFF)] |
             sbox[(pOut32[1] >> 8 & 0xFF)] << 8 |
             sbox[(pOut32[2] >> 16 & 0xFF)] << 16 |
             sbox[(pOut32[3] >> 24 & 0xFF)] << 24;
    tmp[1] = sbox[(pOut32[1] & 0xFF)] |
             sbox[(pOut32[2] >> 8 & 0xFF)] << 8 |
             sbox[(pOut32[3] >> 16 & 0xFF)] << 16 |
             sbox[(pOut32[0] >> 24 & 0xFF)] << 24;
    tmp[2] = sbox[(pOut32[2] & 0xFF)] |
             sbox[(pOut32[3] >> 8 & 0xFF)] << 8 |
             sbox[(pOut32[0] >> 16 & 0xFF)] << 16 |
             sbox[(pOut32[1] >> 24 & 0xFF)] << 24;
    tmp[3] = sbox[(pOut32[3] & 0xFF)] |
             sbox[(pOut32[0] >> 8 & 0xFF)] << 8 |
             sbox[(pOut32[1] >> 16 & 0xFF)] << 16 |
             sbox[(pOut32[2] >> 24 & 0xFF)] << 24;

    /* Add roundkey */
    for(uint8_t i = 0; i < 4; i++) {
        pOut32[i] = tmp[i] ^ m_RoundKeys[m_Rounds - 1][i];
    }
}

template class AesEncryptImpl<128>;
template class AesEncryptImpl<192>;
template class AesEncryptImpl<256>;

} // namespace detail
} // namespace crypto
