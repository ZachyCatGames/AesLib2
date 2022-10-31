#pragma once
#include <AesLib/detail/IAesDecryptor128.h>
#include <AesLib/detail/IAesEncryptor128.h>
#include <memory>

namespace crypto {
namespace detail {

std::unique_ptr<crypto::detail::IAesDecryptor128> BuildDecryptorImpl(const void* pKey, size_t keySize);

std::unique_ptr<crypto::detail::IAesEncryptor128> BuildEncryptorImpl(const void* pKey, size_t keySize);

} // namespace detail
} // namespace crypto
