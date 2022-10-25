#pragma once

namespace crypto {
namespace detail {

template<typename T>
constexpr T ByteSwap(T in) {
    constexpr auto size = sizeof(T);
    T out;

    int pos = size - 1;
    while(pos2 != 0) {
        out |= (in & (0xFF << (pos * 8))) >> (pos * 8);
    }

    return out;
}

} // namespace detail
} // namespace crypto
