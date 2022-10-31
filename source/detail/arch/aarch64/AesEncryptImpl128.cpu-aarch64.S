.text

.global _ZN6crypto6detail4arch7aarch6417AesEncryptImpl12810InitializeEPKvm
.global _ZN6crypto6detail4arch7aarch6417AesEncryptImpl12812EncryptBlockEPvPKv

// void crypto::detail::arch::aarch64::AesEncryptImpl128::Initialize(const void* pKey, size_t keySize);
// X0[in] crypto::detail::AesEncryptImpl128* this
// X1[in] const void* pKey
// X2[in] size_t keySize
_ZN6crypto6detail4arch7aarch6417AesEncryptImpl12810InitializeEPKvm:
    stp     fp, lr, [sp, #-0x10]!
    ldr     Q0, [X1]                        // Save provided key.
    str     Q0, [X0]
    bl      _ZN6crypto6detail19AesExpandKeyImpl128EPv
    ldp     fp, lr, [sp], #0x10
    ret

// void crypto::detail::arch::aarch64::AesEncryptImpl128::EncryptBlock(void* pOut, const void* pIn);
// X0[in] crypto::detail::AesEncryptImpl128* this
// X1[in] void* pOut
// X2[in] const void* pIn
// Note: m_RoundKeys is at offset 0x0 in crypto::detail::AesEncryptImpl128
_ZN6crypto6detail4arch7aarch6417AesEncryptImpl12812EncryptBlockEPvPKv:
    ldr     Q0, [X2]                        // Load input.
    ldr     Q1, [X0]                        // Load first key.
    aese    v0.16B, v1.16B                  // Perform first round
    aesmc   v0.16B, v0.16B
    ldr     Q1, [X2, #0x10]                 // Load second key.
    aese    v0.16B, v1.16B                  // Perform second round.
    aesmc   v0.16B, v0.16B
    ldr     Q1, [X2, #0x20]                 // Load third key.
    aese    v0.16B, v1.16B                  // Perform third round.
    aesmc   v0.16B, v0.16B
    ldr     Q1, [X2, #0x30]                 // Load fourth key.
    aese    v0.16B, v1.16B                  // Perform fourth round.
    aesmc   v0.16B, v0.16B
    ldr     Q1, [X2, #0x40]                 // Load fifth key.
    aese    v0.16B, v1.16B                  // Perform fifth round.
    aesmc   v0.16B, v0.16B
    ldr     Q1, [X2, #0x50]                 // Load sixth key.
    aese    v0.16B, v1.16B                  // Perform sixth round.
    aesmc   v0.16B, v0.16B
    ldr     Q1, [X2, #0x60]                 // Load seventh key.
    aese    v0.16B, v1.16B                  // Perform seventh round.
    aesmc   v0.16B, v0.16B
    ldr     Q1, [X2, #0x70]                 // Load eighth key.
    aese    v0.16B, v1.16B                  // Perform eighth round.
    aesmc   v0.16B, v0.16B
    ldr     Q1, [X2, #0x80]                 // Load ninth key.
    aese    v0.16B, v1.16B                  // Perform ninth round.
    aesmc   v0.16B, v0.16B
    ldr     Q1, [X2, #0x90]                 // Load tenth key.
    aese    v0.16B, v1.16B                  // Perform tenth round.
    ldr     Q1, [X2, #0xA0]                 // Load last key.
    eor     v0.16B, v0.16B, v1.16B          // XOR w/ last key.
    str     Q0, [X1]                        // Store result.
    ret
