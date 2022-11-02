#include <AesLib/detail/AesDecryptImpl.cpu-generic.h>
#include <AesLib/detail/AesExpandKeyImpl.h>
#include <AesLib/detail/AesLookupTables.h>

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
    std::memcpy(m_RoundKeys[0], pKey, KeySize);
    crypto::detail::AesExpandKeyImpl<KeyLength>(m_RoundKeys[0]);
}

template<int KeyLength>
void AesDecryptImpl<KeyLength>::Finalize() {
    /* ... */
}

template<int KeyLength>
void AesDecryptImpl<KeyLength>::DecryptBlock(void* pOut, const void* pIn) {
    constexpr const uint8_t roundCount = 9;
    uint8_t tmp[16] = {0};
    uint32_t* tmp32 = reinterpret_cast<uint32_t*>(tmp);
    auto output = static_cast<uint8_t*>(pOut);
    auto input = static_cast<const uint8_t*>(pIn);
    auto out_u32 = static_cast<uint32_t*>(pOut);
    auto in_u32 = static_cast<const uint32_t*>(pIn);

    /* Subtract Last Roundkey */
    for(uint8_t i = 0; i < 4; i++) {
        reinterpret_cast<uint32_t*>(tmp)[i] = reinterpret_cast<const uint32_t*>(input)[i] ^ reinterpret_cast<uint32_t*>(m_RoundKeys[m_Rounds - 1])[i];
    }

    /* Un-shift rows and invserse subsitution. */
    out_u32[0] = (inv_s[((tmp32[0] >> 0x00) & 0xFF)] << 0x00) |
                 (inv_s[((tmp32[3] >> 0x08) & 0xFF)] << 0x08) |
                 (inv_s[((tmp32[2] >> 0x10) & 0xFF)] << 0x10) |
                 (inv_s[((tmp32[1] >> 0x18) & 0xFF)] << 0x18);

    out_u32[1] = (inv_s[((tmp32[1] >> 0x00) & 0xFF)] << 0x00) |
                 (inv_s[((tmp32[0] >> 0x08) & 0xFF)] << 0x08) |
                 (inv_s[((tmp32[3] >> 0x10) & 0xFF)] << 0x10) |
                 (inv_s[((tmp32[2] >> 0x18) & 0xFF)] << 0x18);

    out_u32[2] = (inv_s[((tmp32[2] >> 0x00) & 0xFF)] << 0x00) |
                 (inv_s[((tmp32[1] >> 0x08) & 0xFF)] << 0x08) |
                 (inv_s[((tmp32[0] >> 0x10) & 0xFF)] << 0x10) |
                 (inv_s[((tmp32[3] >> 0x18) & 0xFF)] << 0x18);

    out_u32[3] = (inv_s[((tmp32[3] >> 0x00) & 0xFF)] << 0x00) |
                 (inv_s[((tmp32[2] >> 0x08) & 0xFF)] << 0x08) |
                 (inv_s[((tmp32[1] >> 0x10) & 0xFF)] << 0x10) |
                 (inv_s[((tmp32[0] >> 0x18) & 0xFF)] << 0x18);


    for(uint8_t round = m_Rounds - 2; round > 0; round--) {
        /* Subtract Roundkey */
        for(uint8_t i = 0; i < 4; i++) {
            reinterpret_cast<uint32_t*>(tmp)[i] = reinterpret_cast<uint32_t*>(output)[i] ^ reinterpret_cast<uint32_t*>(m_RoundKeys[round])[i];
        }

        /* Unmix Columns, Shift Rows, and Inverse Subsitute Bytes */
        output[0]  = inv_s[mul14[tmp[0]] ^ mul11[tmp[1]] ^ mul13[tmp[2]] ^ mul9[tmp[3]]];
        output[5]  = inv_s[mul9[tmp[0]]  ^ mul14[tmp[1]] ^ mul11[tmp[2]] ^ mul13[tmp[3]]];
        output[10] = inv_s[mul13[tmp[0]] ^ mul9[tmp[1]]  ^ mul14[tmp[2]] ^ mul11[tmp[3]]];
        output[15] = inv_s[mul11[tmp[0]] ^ mul13[tmp[1]] ^ mul9[tmp[2]]  ^ mul14[tmp[3]]];

        output[4]  = inv_s[mul14[tmp[4]] ^ mul11[tmp[5]] ^ mul13[tmp[6]] ^ mul9[tmp[7]]];
        output[9]  = inv_s[mul9[tmp[4]]  ^ mul14[tmp[5]] ^ mul11[tmp[6]] ^ mul13[tmp[7]]];
        output[14] = inv_s[mul13[tmp[4]] ^ mul9[tmp[5]]  ^ mul14[tmp[6]] ^ mul11[tmp[7]]];
        output[3]  = inv_s[mul11[tmp[4]] ^ mul13[tmp[5]] ^ mul9[tmp[6]]  ^ mul14[tmp[7]]];

        output[8]  = inv_s[mul14[tmp[8]]  ^ mul11[tmp[9]] ^ mul13[tmp[10]] ^ mul9[tmp[11]]];
        output[13] = inv_s[mul9[tmp[8]]   ^ mul14[tmp[9]] ^ mul11[tmp[10]] ^ mul13[tmp[11]]];
        output[2]  = inv_s[mul13[tmp[8]]  ^ mul9[tmp[9]]  ^ mul14[tmp[10]] ^ mul11[tmp[11]]];
        output[7]  = inv_s[mul11[tmp[8]]  ^ mul13[tmp[9]] ^ mul9[tmp[10]]  ^ mul14[tmp[11]]]; 

        output[12] = inv_s[mul14[tmp[12]] ^ mul11[tmp[13]] ^ mul13[tmp[14]] ^ mul9[tmp[15]]];
        output[1]  = inv_s[mul9[tmp[12]]  ^ mul14[tmp[13]] ^ mul11[tmp[14]] ^ mul13[tmp[15]]];
        output[6]  = inv_s[mul13[tmp[12]] ^ mul9[tmp[13]]  ^ mul14[tmp[14]] ^ mul11[tmp[15]]];
        output[11] = inv_s[mul11[tmp[12]] ^ mul13[tmp[13]] ^ mul9[tmp[14]]  ^ mul14[tmp[15]]]; 
    }

    /* Substract First Roundkey */
    for(uint8_t i = 0; i < 4; i++) {
        reinterpret_cast<uint32_t*>(output)[i] ^= reinterpret_cast<uint32_t*>(m_RoundKeys[0])[i];
    }
}

template class AesDecryptImpl<128>;
template class AesDecryptImpl<192>;
template class AesDecryptImpl<256>;

} // namespace detail
} // namespace crypto
