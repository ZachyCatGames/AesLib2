#pragma once
#include <AesLib/detail/IAesDecryptor128.h>
#include <AesLib/detail/IAesEncryptor128.h>
#include <memory>

namespace crypto {
namespace detail {

template<typename... Args>
std::unique_ptr<crypto::detail::IAesDecryptor128> BuildDecryptor(Args... args);

template<typename... Args>
std::unique_ptr<crypto::detail::IAesEncryptor128> BuildEncryptor(Args... args);

} // namespace detail
} // namespace crypto
