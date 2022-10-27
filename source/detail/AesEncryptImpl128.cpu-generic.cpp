#include <AesLib/detail/AesEncryptImpl128.cpu-generic.h>
#include <AesLib/AesLookupTables.h>
#include <AesLib/detail/AesByteSwap.h>

namespace crypto {
namespace detail {

AesEncryptImpl128::AesEncryptImpl128() = default;

AesEncryptImpl128::AesEncryptImpl128(const void* pKey, size_t keySize) {
    this->Initialize(pKey, keySize);
}

AesEncryptImpl128::~AesEncryptImpl128() = default;

void AesEncryptImpl128::Initialize(const void* pKey, size_t keySize) {
    std::memcpy(m_RoundKeys[0], pKey, 0x10);
    this->ExpandKeyImpl();
}

void AesEncryptImpl128::Finalize() {
    /* ... */
}

void AesEncryptImpl128::ExpandKeyImpl() {
    for(uint8_t round = 1; round < 11; round++) {
        uint32_t* curKey = m_RoundKeys[round];
        uint32_t* preKey = m_RoundKeys[round - 1];
        uint32_t tmp = m_RoundKeys[round - 1][3];

        /* Subsitute bytes */
        tmp = (sbox[(tmp >> 0x00) & 0xFF] << 0x00) |
              (sbox[(tmp >> 0x08) & 0xFF] << 0x08) |
              (sbox[(tmp >> 0x10) & 0xFF] << 0x10) |
              (sbox[(tmp >> 0x18) & 0xFF] << 0x18);


        /* Rotate bytes. */
        tmp = (tmp >> 0x8) | ((tmp & 0xFF) << 0x18);

        /* Handle first word. */
        curKey[0] = preKey[0] ^ tmp ^ rcon[round];

        /* XOR each word with the previous word from the previous key. */
        curKey[1] = curKey[0] ^ preKey[1];
        curKey[2] = curKey[1] ^ preKey[2];
        curKey[3] = curKey[2] ^ preKey[3];
    }
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
