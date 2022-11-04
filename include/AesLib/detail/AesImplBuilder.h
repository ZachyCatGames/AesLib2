#pragma once
#include <AesLib/detail/IAesDecryptor.h>
#include <AesLib/detail/IAesEncryptor.h>
#include <memory>

namespace crypto {
namespace detail {

template<int KeyLength, typename... Args>
std::unique_ptr<crypto::detail::IAesDecryptor<KeyLength>> BuildDecryptor(Args... args);

template<int KeyLength, typename... Args>
std::unique_ptr<crypto::detail::IAesEncryptor<KeyLength>> BuildEncryptor(Args... args);

} // namespace detail
} // namespace crypto
