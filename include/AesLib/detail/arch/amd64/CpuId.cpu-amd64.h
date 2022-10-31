#pragma once

namespace crypto {
namespace detail {
namespace arch {
namespace amd64 {

void GetCpuId(int funcId, int* pEAX, int* pEBX, int* pECX, int* pEDX);

} // namespace amd64
} // namespace arch
} // namespace detail
} // namespace crypto
