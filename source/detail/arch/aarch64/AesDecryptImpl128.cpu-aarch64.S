.text

.global _ZN6crypto6detail4arch7aarch6417AesDecryptImpl12810InitializeEPKvm
.global _ZN6crypto6detail4arch7aarch6417AesDecryptImpl12812DecryptBlockEPvPKv

// void crypto::detail::arch::aarch64::AesDecryptImpl128::Initialize(const void* pKey, size_t keySize);
// X0[in] crypto::detail::AesDecryptImpl128* this
// X1[in] const void* pKey
// X2[in] size_t keySize
_ZN6crypto6detail4arch7aarch6417AesDecryptImpl12810InitializeEPKvm:
    stp     fp, lr, [sp, #-0x10]!
    str     X0, [sp, #-0x10]!               // Save this
    ldr     Q0, [X1]                        // Save provided key.
    str     Q0, [X0]
    bl      _ZN6crypto6detail19AesExpandKeyImpl128EPv
    ldr     X0, [sp], #0x10
    ldp     Q0, Q1, [X0, #0x10]             // Inverse mix columns on key 1 & 2
    aesimc  v0.16B, v0.16B
    aesimc  v1.16B, v1.16B
    stp     Q0, Q1, [X0, #0x10]
    ldp     Q0, Q1, [X0, #0x30]             // Inverse mix columns on key 3 & 4
    aesimc  v0.16B, v0.16B
    aesimc  v1.16B, v1.16B
    stp     Q0, Q1, [X0, #0x30]
    ldp     Q0, Q1, [X0, #0x50]             // Inverse mix columns on key 5 & 6
    aesimc  v0.16B, v0.16B
    aesimc  v1.16B, v1.16B
    stp     Q0, Q1, [X0, #0x50]
    ldp     Q0, Q1, [X0, #0x70]             // Inverse mix columns on key 7 & 8
    aesimc  v0.16B, v0.16B
    aesimc  v1.16B, v1.16B
    stp     Q0, Q1, [X0, #0x70]
    ldr     Q0, [X0, #0x90]                 // Inverse mix columns on key 9.
    aesimc  v0.16B, v0.16B
    str     Q0, [X0, #0x90]
    ldp     fp, lr, [sp], #0x10
    ret

// void crypto::detail::arch::aarch64::AesDecryptImpl128::DecryptBlock(void* pOut, const void* pIn);
// X0[in] crypto::detail::AesDecryptImpl128* this
// X1[in] void* pOut
// X2[in] const void* pIn
// Note: m_RoundKeys is at offset 0x0 in crypto::detail::AesDecryptImpl128
_ZN6crypto6detail4arch7aarch6417AesDecryptImpl12812DecryptBlockEPvPKv:
    ldr     Q0, [X2]                        // Load input.
    ldr     Q1, [X0, #0xA0]                 // Load first key.
    aesd    v0.16B, v1.16B                  // Perform first round.
    aesimc  v0.16B, v0.16B
    ldr     Q1, [X0, #0x90]                 // Load second key.
    aesd    v0.16B, v1.16B                  // Perform second round.
    aesimc  v0.16B, v0.16B
    ldr     Q1, [X0, #0x80]                 // Load third key.
    aesd    v0.16B, v1.16B                  // Perform third round.
    aesimc  v0.16B, v0.16B
    ldr     Q1, [X0, #0x70]                  // Load fourth key.
    aesd    v0.16B, v1.16B                  // Perform fourth round.
    aesimc  v0.16B, v0.16B
    ldr     Q1, [X0, #0x60]                 // Load fifth key.
    aesd    v0.16B, v1.16B                  // Perform fifth round.
    aesimc  v0.16B, v0.16B
    ldr     Q1, [X0, #0x50]                 // Load sixth key.
    aesd    v0.16B, v1.16B                  // Perform sixth round.
    aesimc  v0.16B, v0.16B
    ldr     Q1, [X0, #0x40]                 // Load seventh key.
    aesd    v0.16B, v1.16B                  // Perform seventh round.
    aesimc  v0.16B, v0.16B
    ldr     Q1, [X0, #0x30]                 // Load eighth key.
    aesd    v0.16B, v1.16B                  // Perform eighth round.
    aesimc  v0.16B, v0.16B
    ldr     Q1, [X0, #0x20]                 // Load ninth key.
    aesd    v0.16B, v1.16B                  // Perform ninth round.
    aesimc  v0.16B, v0.16B
    ldr     Q1, [X0, #0x10]                 // Load tenth key.
    aesd    v0.16B, v1.16B                  // Perform tenth round.
    ldr     Q1, [X0]                        // Load last key.
    eor     v0.16B, v0.16B, v1.16B          // XOR w/ last key.
    str     Q0, [X1]                        // Store result.
    ret
