#include <AesLib/detail/arch/amd64/CpuId.cpu-amd64.h>

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace crypto {
namespace detail {
namespace arch {
namespace amd64 {

void GetCpuId(int funcId, int* pEAX, int* pEBX, int* pECX, int* pEDX) {
#ifdef _MSC_VER
    int regs[4];
    __cpuid(regs, 1);

    /* Return values. */
    *pEAX = regs[0];
    *pEBX = regs[1];
    *pECX = regs[2];
    *pEDX = regs[3];
#else
    int a, b, c, d;
    asm("cpuid\n\t"
        : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
        : "0" (funcId)
    );

    /* Return values. */
    *pEAX = a;
    *pEBX = b;
    *pECX = c;
    *pEDX = d;
#endif

}

} // namespace amd64
} // namespace arch
} // namespace detail
} // namespace crypto
