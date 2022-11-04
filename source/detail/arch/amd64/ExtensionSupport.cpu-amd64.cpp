#include <AesLib/detail/arch/amd64/ExtensionSupport.cpu-amd64.h>
#include <AesLib/detail/arch/amd64/CpuId.cpu-amd64.h>

namespace crypto {
namespace detail {
namespace arch {
namespace amd64 {

bool SupportsAesExtensions() {
    int eax, ebx, ecx, edx;

    /* Get CpuId. */
    crypto::detail::arch::amd64::GetCpuId(1, &eax, &ebx, &ecx, &edx);

    return ecx & (1 << 25);
}

} // namespace amd64
} // namespace arch
} // namespace detail
} // namespace crypto
