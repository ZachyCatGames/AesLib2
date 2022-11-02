#pragma once

namespace crypto {
namespace detail {

template<int KeyLength>
void AesExpandKeyImpl(void* pKeyData);

} // namespace detail
} // namespace crypto
