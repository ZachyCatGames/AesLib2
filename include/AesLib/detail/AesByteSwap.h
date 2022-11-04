#pragma once

namespace crypto {
namespace detail {

template<typename T>
constexpr T ByteSwap(T in) {
    constexpr auto size = sizeof(T);
    T out = 0;

    int pos = size - 1;
    int shift = size - 1;
    while(pos != 0) {
        if(shift > 0) {
            out |= (in & (0xFF << (pos * 8))) >> (shift * 8);
        }
        else {
            out |= (in & (0xFF << (pos * 8))) << (-1 * shift * 8);
        }
        --pos;
        shift -= 2;
    }

    /* Handle last bytes. */
    out |= in << (size - 1) * 8;

    return out;
}

} // namespace detail
} // namespace crypto
