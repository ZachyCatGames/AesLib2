.text

.global _ZN6crypto6detail4arch7aarch6414AesDecryptImplILi256EE10InitializeEPKvm
.global _ZN6crypto6detail4arch7aarch6414AesDecryptImplILi256EE12DecryptBlockEPvPKv

// NOTE: Keys are located at offset 0x10 due to vtable shit.

// void crypto::detail::arch::aarch64::AesDecryptImpl<256>::Initialize(const void* pKey, size_t keySize);
// X0[in] crypto::detail::AesDecryptImpl<256>* this
// X1[in] const void* pKey
// X2[in] size_t keySize
_ZN6crypto6detail4arch7aarch6414AesDecryptImplILi256EE10InitializeEPKvm:
    stp     fp, lr, [sp, #-0x20]!                                   // Save fp/lr context.
    mov     fp, sp
    str     X0, [sp, #0x10]
    ld1     {v0.16B}, [X1]                                          // Copy provided key to our structure.
    st1     {v0.16B}, [X0]
    bl      _ZN6crypto6detail16AesExpandKeyImplILi256EEEvPv         // Expand key.
    ldr     X0, [sp, #0x10]                                         // Reload this.
    add     X0, X0, #0x20                                           // Start at offset 0x20 (key1)
    ld1     {v0.16B, v1.16B, v2.16B, v3.16B}, [X0]                  // Inverse mix columns on keys 1,2,3,4
    aesimc  v0.16B, v0.16B
    aesimc  v1.16B, v1.16B
    aesimc  v2.16B, v2.16B
    aesimc  v3.16B, v3.16B
    st1     {v0.16B, v1.16B, v2.16B, v3.16B}, [X0], #0x40
    ld1     {v0.16B, v1.16B, v2.16B, v3.16B}, [X0]                  // Inverse mix columns on keys 5,6,7,8
    aesimc  v0.16B, v0.16B
    aesimc  v1.16B, v1.16B
    aesimc  v2.16B, v2.16B
    aesimc  v3.16B, v3.16B
    st1     {v0.16B, v1.16B, v2.16B, v3.16B}, [X0], #0x40
    ld1     {v0.16B, v1.16B, v2.16B, v3.16B}, [X0]                  // Inverse mix columns on keys 9,10,11,12
    aesimc  v0.16B, v0.16B
    aesimc  v1.16B, v1.16B
    aesimc  v2.16B, v2.16B
    aesimc  v3.16B, v3.16B
    st1     {v0.16B, v1.16B, v2.16B, v3.16B}, [X0], #0x40
    ld1     {v0.16B}, [X0]
    aesimc  v0.16B, v0.16B
    st1     {v0.16B}, [X0]
    stp     fp, lr, [sp], #0x20                                     // Load previous fp/lr context.
    ret

// void crypto::detail::arch::aarch64::AesDecryptImpl<256>::DecryptBlock(void* pOut, const void* pIn);
// X0[in] crypto::detail::AesDecryptImpl<256>* this
// X1[in] void* pOut
// X2[in] const void* pIn
_ZN6crypto6detail4arch7aarch6414AesDecryptImplILi256EE12DecryptBlockEPvPKv:
    add     X0, X0, #0x10                                           // Increment this to the offset of the keys.
    ld1     {v0.16B}, [X2]
    ld1     {v1.16B, v2.16B, v3.16B, v4.16B}, [X0], #0x40           // Load keys 0,1,2,3
    aesd    v0.16B, v1.16B                                          // Perform 0th round.
    aesimc  v0.16B, v0.16B
    aesd    v0.16B, v2.16B                                          // Perform 1st round.
    aesimc  v0.16B, v0.16B
    aesd    v0.16B, v3.16B                                          // Perform 2nd round.
    aesimc  v0.16B, v0.16B
    aesd    v0.16B, v4.16B                                          // Perform 3rd round.
    aesimc  v0.16B, v0.16B
    ld1     {v1.16B, v2.16B, v3.16B, v4.16B}, [X0], #0x40           // Load keys 4,5,6,7
    aesd    v0.16B, v1.16B                                          // Perform 5th round.
    aesimc  v0.16B, v0.16B
    aesd    v0.16B, v2.16B                                          // Perform 6th round.
    aesimc  v0.16B, v0.16B
    aesd    v0.16B, v3.16B                                          // Perform 7th round.
    aesimc  v0.16B, v0.16B
    aesd    v0.16B, v4.16B                                          // Perform 8th round.
    aesimc  v0.16B, v0.16B
    ld1     {v1.16B, v2.16B, v3.16B, v4.16B}, [X0], #0x40           // Load keys 8,9,10,11
    aesd    v0.16B, v1.16B                                          // Perform 9th round.
    aesimc  v0.16B, v0.16B
    aesd    v0.16B, v2.16B                                          // Perform 10th round.
    aesimc  v0.16B, v0.16B
    aesd    v0.16B, v3.16B                                          // Perform 11th round.
    aesimc  v0.16B, v0.16B
    aesd    v0.16B, v4.16B                                          // Perform 12th round.
    aesimc  v0.16B, v0.16B
    ld1     {v1.16B, v2.16B, v3.16B}, [X0]                          // Load keys 12,13,14
    aesd    v0.16B, v1.16B                                          // Perform 13th round.
    aesimc  v0.16B, v0.16B
    aesd    v0.16B, v2.16B                                          // Perform 14th round.
    eor     v0.16B, v0.16B, v3.16B                                  // XOR w/ last key.
    st1     {v0.16B}, [X1]                                          // Store result.
    ret
