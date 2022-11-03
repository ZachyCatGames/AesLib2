.text

.global _ZN6crypto6detail4arch7aarch6414AesEncryptImplILi192EE10InitializeEPKvm
.global _ZN6crypto6detail4arch7aarch6414AesEncryptImplILi192EE12EncryptBlockEPvPKv

// NOTE: Keys are located at offset 0x10 due to vtable shit.

// void crypto::detail::arch::aarch64::AesEncryptImpl128::Initialize(const void* pKey, size_t keySize);
// X0[in] crypto::detail::AesEncryptImpl128* this
// X1[in] const void* pKey
// X2[in] size_t keySize
_ZN6crypto6detail4arch7aarch6414AesEncryptImplILi192EE10InitializeEPKvm:
    stp     fp, lr, [sp, #-0x10]!
    add     X0, X0, #0x10
    ld1     {v0.16B}, [X1]                                          // Save provided key.
    st1     {v0.16B}, [X0]
    bl      _ZN6crypto6detail16AesExpandKeyImplILi192EEEvPv
    ldp     fp, lr, [sp], #0x10
    ret

// void crypto::detail::arch::aarch64::AesEncryptImpl128::EncryptBlock(void* pOut, const void* pIn);
// X0[in] crypto::detail::AesEncryptImpl128* this
// X1[in] void* pOut
// X2[in] const void* pIn
// Note: m_RoundKeys is at offset 0x0 in crypto::detail::AesEncryptImpl128
_ZN6crypto6detail4arch7aarch6414AesEncryptImplILi192EE12EncryptBlockEPvPKv:
    add     X0, X0, #0x10                                           // Increment this to key offset.
    ld1     {v0.16B}, [X2]                                          // Load input.
    ld1     {v1.16B, v2.16B, v3.16B, v4.16B}, [X0], #0x40           // Load keys 0,1,2,3
    aese    v0.16B, v1.16B                                          // Perform 0th round
    aesmc   v0.16B, v0.16B
    aese    v0.16B, v2.16B                                          // Perform 1st round.
    aesmc   v0.16B, v0.16B
    aese    v0.16B, v3.16B                                          // Perform 2nd round.
    aesmc   v0.16B, v0.16B
    aese    v0.16B, v4.16B                                          // Perform 3rd round.
    aesmc   v0.16B, v0.16B
    ld1     {v1.16B, v2.16B, v3.16B, v4.16B}, [X0], #0x40           // Load keys 4,5,6,7
    aese    v0.16B, v1.16B                                          // Perform 4th round.
    aesmc   v0.16B, v0.16B
    aese    v0.16B, v2.16B                                          // Perform 5th round.
    aesmc   v0.16B, v0.16B
    aese    v0.16B, v3.16B                                          // Perform 6th round.
    aesmc   v0.16B, v0.16B
    aese    v0.16B, v4.16B                                          // Perform 7th round.
    aesmc   v0.16B, v0.16B
    ld1     {v1.16B, v2.16B, v3.16B, v4.16B}, [X0], #0x40           // Load keys 8,9,10,11
    aese    v0.16B, v1.16B                                          // Perform 8th round.
    aesmc   v0.16B, v0.16B
    aese    v0.16B, v2.16B                                          // Perform 9th round.
    aesmc   v0.16B, v0.16B
    aese    v0.16B, v3.16B                                          // Perform 10th round.
    aesmc   v0.16B, v0.16B
    aese    v0.16B, v4.16B                                          // Perform 11th round.
    ld1     {v1.16B}, [X0]                                          // Load key 12
    eor     v0.16B, v0.16B, v1.16B                                  // XOR w/ last key.
    st1     {v0.16B}, [X1]                                          // Store result.
    ret
