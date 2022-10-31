#include <AesLib/detail/AesGFMul.h>
#include <cstdint>

namespace crypto {
namespace detail {

//https://www.oryx-embedded.com/doc/xts_8c_source.html
void GFMul(void* pOut, const void* pIn) {
    uint8_t carry;
    uint8_t* out_ptr = static_cast<uint8_t*>(pOut);
    const uint8_t* in_ptr = static_cast<const uint8_t*>(pIn);

    //Save the value of the most significant bit
    carry = in_ptr[15] >> 7;

    //The multiplication of a polynomial by x in GF(2^128) corresponds to a
    //shift of indices
    for(int i = 15; i > 0; i--)
    {
        out_ptr[i] = (in_ptr[i] << 1) | (in_ptr[i - 1] >> 7);
    }

    //Shift the first byte of the block
    out_ptr[0] = in_ptr[0] << 1;

    //If the highest term of the result is equal to one, then perform reduction
    out_ptr[0] ^= 0x87 & ~(carry - 1);
}

} // namespace detail
} // namespace crypto
