namespace crypto {
namespace detail {
namespace arch {
namespace amd64 {

void GetCpuId(int funcId, int* pEAX, int* pEBX, int* pECX, int* pEDX) {
    int a, b, c, d;

    asm ( "cpuid\n\t"
        : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
        : "0" (funcId)
    );

    /* Return values. */
    *pEAX = a;
    *pEBX = b;
    *pECX = c;
    *pEDX = d;
}

} // namespace amd64
} // namespace arch
} // namespace detail
} // namespace crypto
