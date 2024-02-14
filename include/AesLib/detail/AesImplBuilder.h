#pragma once
#include <AesLib/detail/IAesDecryptor.h>
#include <AesLib/detail/IAesEncryptor.h>
#include <memory>

namespace crypto {
namespace detail {

template<int KeyLength>
UniqueDecryptor BuildDecryptor();

template<int KeyLength>
UniqueDecryptor BuildDecryptor(const void* pKey, std::size_t keySize);

template<int KeyLength>
UniqueEncryptor BuildEncryptor();

template<int KeyLength>
UniqueEncryptor BuildEncryptor(const void* pKey, std::size_t keySize);

} // namespace detail
} // namespace crypto
