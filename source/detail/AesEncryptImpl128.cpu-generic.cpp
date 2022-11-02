#include <AesLib/detail/AesEncryptImpl128.cpu-generic.h>
#include <AesLib/detail/AesExpandKeyImpl.h>
#include <AesLib/detail/AesLookupTables128.h>
#include <AesLib/detail/AesByteSwap.h>

namespace crypto {
namespace detail {

AesEncryptImpl128::AesEncryptImpl128() = default;

AesEncryptImpl128::AesEncryptImpl128(const void* pKey, size_t keySize) {
    std::memcpy(m_RoundKeys[0], pKey, 0x10);
    crypto::detail::AesExpandKeyImpl<128>(m_RoundKeys[0]);
}

AesEncryptImpl128::~AesEncryptImpl128() = default;

void AesEncryptImpl128::Initialize(const void* pKey, size_t keySize) {
    std::memcpy(m_RoundKeys[0], pKey, 0x10);
    crypto::detail::AesExpandKeyImpl<128>(m_RoundKeys[0]);
}

void AesEncryptImpl128::Finalize() {
    /* ... */
}

void AesEncryptImpl128::EncryptBlock(void* pOut, const void* pIn) {
    constexpr const uint8_t roundCount = 9;
    const uint32_t* pIn32 = static_cast<const uint32_t*>(pIn);
    uint32_t* pOut32 = static_cast<uint32_t*>(pOut);
    uint32_t tmp[4];

    /* Add roundkey */
    for(uint8_t i = 0; i < 4; i++) {
        pOut32[i] = pIn32[i] ^ m_RoundKeys[0][i];
    }

    /* Shift Rows Right, Mix Columns, and Subsitute. */
    for(uint8_t round = 1; round <= roundCount; round++) {
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
        pOut32[i] = tmp[i] ^ m_RoundKeys[10][i];
    }
}

} // namespace detail
} // namespace crypto
