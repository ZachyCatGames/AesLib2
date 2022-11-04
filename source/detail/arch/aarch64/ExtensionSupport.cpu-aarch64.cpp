#include <AesLib/detail/arch/aarch64/ExtensionSupport.cpu-aarch64.h>
#include <cstdint>

namespace crypto {
namespace detail {
namespace arch {
namespace aarch64 {

bool SupportsAesExtensions() {
    /* Read extension info. */
    uint64_t id_aa64isar0;
    asm volatile("mrs %0, id_aa64isar0_el1" : "=r" (id_aa64isar0));

    /* Return AES extension support. */
    return id_aa64isar0 & (1 << 4);
}

} // namespace aarch64
} // namespace arch
} // namespace detail
} // namespace crypto
