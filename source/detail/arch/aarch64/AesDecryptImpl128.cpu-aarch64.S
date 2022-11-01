.text

.global _ZN6crypto6detail4arch7aarch6417AesDecryptImpl12810InitializeEPKvm
.global _ZN6crypto6detail4arch7aarch6417AesDecryptImpl12812DecryptBlockEPvPKv

// NOTE: Keys are located at offset 0x10 due to vtable shit.

// void crypto::detail::arch::aarch64::AesDecryptImpl128::Initialize(const void* pKey, size_t keySize);
// X0[in] crypto::detail::AesDecryptImpl128* this
// X1[in] const void* pKey
// X2[in] size_t keySize
_ZN6crypto6detail4arch7aarch6417AesDecryptImpl12810InitializeEPKvm:
    stp     fp, lr, [sp, #-0x20]!                                   // Save fp/lr context.
    mov     fp, sp
    str     X0, [sp, #0x10]
    ld1     {v0.16B}, [X1]                                          // Copy provided key to our structure.
    st1     {v0.16B}, [X0]
    bl      _ZN6crypto6detail19AesExpandKeyImpl128EPv               // Expand key.
    ldr     X0, [sp, #0x10]                                         // Reload this.
    add     X0, X0, #0x10
    ld1     {v0.16B}, [X0]                                          // Inverse mix columns on all keys.
    aesimc  v0.16B, v0.16B
    st1     {v0.16B}, [X0], #0x10
    ld1     {v0.16B}, [X0]
    aesimc  v0.16B, v0.16B
    st1     {v0.16B}, [X0], #0x10
    ld1     {v0.16B}, [X0]
    aesimc  v0.16B, v0.16B
    st1     {v0.16B}, [X0], #0x10
    ld1     {v0.16B}, [X0]
    aesimc  v0.16B, v0.16B
    st1     {v0.16B}, [X0], #0x10
    ld1     {v0.16B}, [X0]
    aesimc  v0.16B, v0.16B
    st1     {v0.16B}, [X0], #0x10
    ld1     {v0.16B}, [X0]
    aesimc  v0.16B, v0.16B
    st1     {v0.16B}, [X0], #0x10
    ld1     {v0.16B}, [X0]
    aesimc  v0.16B, v0.16B
    st1     {v0.16B}, [X0], #0x10
    ld1     {v0.16B}, [X0]
    aesimc  v0.16B, v0.16B
    st1     {v0.16B}, [X0], #0x10
    ld1     {v0.16B}, [X0]
    aesimc  v0.16B, v0.16B
    st1     {v0.16B}, [X0], #0x10
    stp     fp, lr, [sp], #0x20                                     // Load previous fp/lr context.
    ret

// void crypto::detail::arch::aarch64::AesDecryptImpl128::DecryptBlock(void* pOut, const void* pIn);
// X0[in] crypto::detail::AesDecryptImpl128* this
// X1[in] void* pOut
// X2[in] const void* pIn
// Note: m_RoundKeys is at offset 0x0 in crypto::detail::AesDecryptImpl128
_ZN6crypto6detail4arch7aarch6417AesDecryptImpl12812DecryptBlockEPvPKv:
    ldr     Q0, [X2]                                                // Load input.
    add     X0, X0, #0x10                                           // Increment this to the offset of the keys.
    ld1     {v0.16B}, [X0], #0x10                                   // Load first key.
    aesd    v0.16B, v1.16B                                          // Perform first round.
    aesimc  v0.16B, v0.16B
    ld1     {v0.16B}, [X0], #0x10                                   // Load second key.
    aesd    v0.16B, v1.16B                                          // Perform second round.
    aesimc  v0.16B, v0.16B
    ld1     {v0.16B}, [X0], #0x10                                   // Load third key.
    aesd    v0.16B, v1.16B                                          // Perform third round.
    aesimc  v0.16B, v0.16B
    ld1     {v0.16B}, [X0], #0x10                                   // Load fourth key.
    aesd    v0.16B, v1.16B                                          // Perform fourth round.
    aesimc  v0.16B, v0.16B
    ld1     {v0.16B}, [X0], #0x10                                   // Load fifth key.
    aesd    v0.16B, v1.16B                                          // Perform fifth round.
    aesimc  v0.16B, v0.16B
    ld1     {v0.16B}, [X0], #0x10                                   // Load sixth key.
    aesd    v0.16B, v1.16B                                          // Perform sixth round.
    aesimc  v0.16B, v0.16B
    ld1     {v0.16B}, [X0], #0x10                                   // Load seventh key.
    aesd    v0.16B, v1.16B                                          // Perform seventh round.
    aesimc  v0.16B, v0.16B
    ld1     {v0.16B}, [X0], #0x10                                   // Load eighth key.
    aesd    v0.16B, v1.16B                                          // Perform eighth round.
    aesimc  v0.16B, v0.16B
    ld1     {v0.16B}, [X0], #0x10                                   // Load ninth key.
    aesd    v0.16B, v1.16B                                          // Perform ninth round.
    aesimc  v0.16B, v0.16B
    ld1     {v0.16B}, [X0], #0x10                                   // Load tenth key.
    aesd    v0.16B, v1.16B                                          // Perform tenth round.
    ld1     {v0.16B}, [X0], #0x10                                   // Load last key.
    eor     v0.16B, v0.16B, v1.16B                                  // XOR w/ last key.
    str     Q0, [X1]                                                // Store result.
    ret
