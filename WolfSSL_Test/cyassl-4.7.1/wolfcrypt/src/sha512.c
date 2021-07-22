/* sha512.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * https://www.wolfssl.com
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_SHA512

#if defined(HAVE_FIPS) && \
    defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)

    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
    #define FIPS_NO_WRAPPERS

    #ifdef USE_WINDOWS_API
        #pragma code_seg(".fipsA$k")
        #pragma const_seg(".fipsB$k")
    #endif
#endif

#if defined(HAVE_FIPS) && \
    defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2) && \
    defined(WOLFSSL_ARMASM)

    /* start of: armv8-sha512-asm.c */
    #ifdef __aarch64__
    #include <wolfssl/wolfcrypt/sha512.h>

    void Transform_Sha512_Len(wc_Sha512* sha512, const byte* data, word32 len);

    static const unsigned long L_SHA512_transform_neon_len_k[] = {
        0x428a2f98d728ae22UL,
        0x7137449123ef65cdUL,
        0xb5c0fbcfec4d3b2fUL,
        0xe9b5dba58189dbbcUL,
        0x3956c25bf348b538UL,
        0x59f111f1b605d019UL,
        0x923f82a4af194f9bUL,
        0xab1c5ed5da6d8118UL,
        0xd807aa98a3030242UL,
        0x12835b0145706fbeUL,
        0x243185be4ee4b28cUL,
        0x550c7dc3d5ffb4e2UL,
        0x72be5d74f27b896fUL,
        0x80deb1fe3b1696b1UL,
        0x9bdc06a725c71235UL,
        0xc19bf174cf692694UL,
        0xe49b69c19ef14ad2UL,
        0xefbe4786384f25e3UL,
        0xfc19dc68b8cd5b5UL,
        0x240ca1cc77ac9c65UL,
        0x2de92c6f592b0275UL,
        0x4a7484aa6ea6e483UL,
        0x5cb0a9dcbd41fbd4UL,
        0x76f988da831153b5UL,
        0x983e5152ee66dfabUL,
        0xa831c66d2db43210UL,
        0xb00327c898fb213fUL,
        0xbf597fc7beef0ee4UL,
        0xc6e00bf33da88fc2UL,
        0xd5a79147930aa725UL,
        0x6ca6351e003826fUL,
        0x142929670a0e6e70UL,
        0x27b70a8546d22ffcUL,
        0x2e1b21385c26c926UL,
        0x4d2c6dfc5ac42aedUL,
        0x53380d139d95b3dfUL,
        0x650a73548baf63deUL,
        0x766a0abb3c77b2a8UL,
        0x81c2c92e47edaee6UL,
        0x92722c851482353bUL,
        0xa2bfe8a14cf10364UL,
        0xa81a664bbc423001UL,
        0xc24b8b70d0f89791UL,
        0xc76c51a30654be30UL,
        0xd192e819d6ef5218UL,
        0xd69906245565a910UL,
        0xf40e35855771202aUL,
        0x106aa07032bbd1b8UL,
        0x19a4c116b8d2d0c8UL,
        0x1e376c085141ab53UL,
        0x2748774cdf8eeb99UL,
        0x34b0bcb5e19b48a8UL,
        0x391c0cb3c5c95a63UL,
        0x4ed8aa4ae3418acbUL,
        0x5b9cca4f7763e373UL,
        0x682e6ff3d6b2b8a3UL,
        0x748f82ee5defb2fcUL,
        0x78a5636f43172f60UL,
        0x84c87814a1f0ab72UL,
        0x8cc702081a6439ecUL,
        0x90befffa23631e28UL,
        0xa4506cebde82bde9UL,
        0xbef9a3f7b2c67915UL,
        0xc67178f2e372532bUL,
        0xca273eceea26619cUL,
        0xd186b8c721c0c207UL,
        0xeada7dd6cde0eb1eUL,
        0xf57d4f7fee6ed178UL,
        0x6f067aa72176fbaUL,
        0xa637dc5a2c898a6UL,
        0x113f9804bef90daeUL,
        0x1b710b35131c471bUL,
        0x28db77f523047d84UL,
        0x32caab7b40c72493UL,
        0x3c9ebe0a15c9bebcUL,
        0x431d67c49c100d4cUL,
        0x4cc5d4becb3e42b6UL,
        0x597f299cfc657e2aUL,
        0x5fcb6fab3ad6faecUL,
        0x6c44198c4a475817UL,
    };

    static const unsigned long L_SHA512_transform_neon_len_ror8[] = {
        0x7060504030201UL,
        0x80f0e0d0c0b0a09UL,
    };

    void Transform_Sha512_Len(wc_Sha512* sha512, const byte* data, word32 len)
    {
        __asm__ __volatile__ (
            "stp	x29, x30, [sp, #-16]!\n\t"
            "add	x29, sp, #0\n\t"
    #ifndef __APPLE__
            "adr	x3, %[L_SHA512_transform_neon_len_k]\n\t"
    #else
            "adrp	x3, %[L_SHA512_transform_neon_len_k]@PAGE\n\t"
            "add	x3, x3, %[L_SHA512_transform_neon_len_k]@PAGEOFF\n\t"
    #endif /* __APPLE__ */
    #ifndef __APPLE__
            "adr	x27, %[L_SHA512_transform_neon_len_ror8]\n\t"
    #else
            "adrp	x27, %[L_SHA512_transform_neon_len_ror8]@PAGE\n\t"
            "add	x27, x27, %[L_SHA512_transform_neon_len_ror8]@PAGEOFF\n\t"
    #endif /* __APPLE__ */
            "ld1	{v11.16b}, [x27]\n\t"
            /* Load digest into working vars */
            "ldp	x4, x5, [%x[sha512]]\n\t"
            "ldp	x6, x7, [%x[sha512], #16]\n\t"
            "ldp	x8, x9, [%x[sha512], #32]\n\t"
            "ldp	x10, x11, [%x[sha512], #48]\n\t"
            /* Start of loop processing a block */
            "\n"
        "L_sha512_len_neon_begin_%=: \n\t"
            /* Load W */
            /* Copy digest to add in at end */
            "ld1	{v0.2d, v1.2d, v2.2d, v3.2d}, [%x[data]], #0x40\n\t"
            "mov	x19, x4\n\t"
            "ld1	{v4.2d, v5.2d, v6.2d, v7.2d}, [%x[data]], #0x40\n\t"
            "mov	x20, x5\n\t"
            "rev64	v0.16b, v0.16b\n\t"
            "mov	x21, x6\n\t"
            "rev64	v1.16b, v1.16b\n\t"
            "mov	x22, x7\n\t"
            "rev64	v2.16b, v2.16b\n\t"
            "mov	x23, x8\n\t"
            "rev64	v3.16b, v3.16b\n\t"
            "mov	x24, x9\n\t"
            "rev64	v4.16b, v4.16b\n\t"
            "mov	x25, x10\n\t"
            "rev64	v5.16b, v5.16b\n\t"
            "mov	x26, x11\n\t"
            "rev64	v6.16b, v6.16b\n\t"
            "rev64	v7.16b, v7.16b\n\t"
            /* Pre-calc: b ^ c */
            "eor	x16, x5, x6\n\t"
            "mov	x27, #4\n\t"
            /* Start of 16 rounds */
            "\n"
        "L_sha512_len_neon_start_%=: \n\t"
            /* Round 0 */
            "mov	x13, v0.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x8, #14\n\t"
            "ror	x14, x4, #28\n\t"
            "eor	x12, x12, x8, ror 18\n\t"
            "eor	x14, x14, x4, ror 34\n\t"
            "eor	x12, x12, x8, ror 41\n\t"
            "eor	x14, x14, x4, ror 39\n\t"
            "add	x11, x11, x12\n\t"
            "eor	x17, x4, x5\n\t"
            "eor	x12, x9, x10\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x8\n\t"
            "add	x11, x11, x13\n\t"
            "eor	x12, x12, x10\n\t"
            "add	x11, x11, x15\n\t"
            "eor	x16, x16, x5\n\t"
            "add	x11, x11, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x7, x7, x11\n\t"
            "add	x11, x11, x14\n\t"
            /* Round 1 */
            "mov	x13, v0.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ext	v10.16b, v0.16b, v1.16b, #8\n\t"
            "ror	x12, x7, #14\n\t"
            "shl	v8.2d, v7.2d, #45\n\t"
            "ror	x14, x11, #28\n\t"
            "sri	v8.2d, v7.2d, #19\n\t"
            "eor	x12, x12, x7, ror 18\n\t"
            "shl	v9.2d, v7.2d, #3\n\t"
            "eor	x14, x14, x11, ror 34\n\t"
            "sri	v9.2d, v7.2d, #61\n\t"
            "eor	x12, x12, x7, ror 41\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x14, x14, x11, ror 39\n\t"
            "ushr	v8.2d, v7.2d, #6\n\t"
            "add	x10, x10, x12\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x16, x11, x4\n\t"
            "add	v0.2d, v0.2d, v9.2d\n\t"
            "eor	x12, x8, x9\n\t"
            "ext	v9.16b, v4.16b, v5.16b, #8\n\t"
            "and	x17, x16, x17\n\t"
            "add	v0.2d, v0.2d, v9.2d\n\t"
            "and	x12, x12, x7\n\t"
            "shl	v8.2d, v10.2d, #63\n\t"
            "add	x10, x10, x13\n\t"
            "sri	v8.2d, v10.2d, #1\n\t"
            "eor	x12, x12, x9\n\t"
            "tbl	v9.16b, {v10.16b}, v11.16b\n\t"
            "add	x10, x10, x15\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x17, x17, x4\n\t"
            "ushr	v10.2d, v10.2d, #7\n\t"
            "add	x10, x10, x12\n\t"
            "eor	v9.16b, v9.16b, v10.16b\n\t"
            "add	x14, x14, x17\n\t"
            "add	v0.2d, v0.2d, v9.2d\n\t"
            "add	x6, x6, x10\n\t"
            "add	x10, x10, x14\n\t"
            /* Round 2 */
            "mov	x13, v1.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x6, #14\n\t"
            "ror	x14, x10, #28\n\t"
            "eor	x12, x12, x6, ror 18\n\t"
            "eor	x14, x14, x10, ror 34\n\t"
            "eor	x12, x12, x6, ror 41\n\t"
            "eor	x14, x14, x10, ror 39\n\t"
            "add	x9, x9, x12\n\t"
            "eor	x17, x10, x11\n\t"
            "eor	x12, x7, x8\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x6\n\t"
            "add	x9, x9, x13\n\t"
            "eor	x12, x12, x8\n\t"
            "add	x9, x9, x15\n\t"
            "eor	x16, x16, x11\n\t"
            "add	x9, x9, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x5, x5, x9\n\t"
            "add	x9, x9, x14\n\t"
            /* Round 3 */
            "mov	x13, v1.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ext	v10.16b, v1.16b, v2.16b, #8\n\t"
            "ror	x12, x5, #14\n\t"
            "shl	v8.2d, v0.2d, #45\n\t"
            "ror	x14, x9, #28\n\t"
            "sri	v8.2d, v0.2d, #19\n\t"
            "eor	x12, x12, x5, ror 18\n\t"
            "shl	v9.2d, v0.2d, #3\n\t"
            "eor	x14, x14, x9, ror 34\n\t"
            "sri	v9.2d, v0.2d, #61\n\t"
            "eor	x12, x12, x5, ror 41\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x14, x14, x9, ror 39\n\t"
            "ushr	v8.2d, v0.2d, #6\n\t"
            "add	x8, x8, x12\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x16, x9, x10\n\t"
            "add	v1.2d, v1.2d, v9.2d\n\t"
            "eor	x12, x6, x7\n\t"
            "ext	v9.16b, v5.16b, v6.16b, #8\n\t"
            "and	x17, x16, x17\n\t"
            "add	v1.2d, v1.2d, v9.2d\n\t"
            "and	x12, x12, x5\n\t"
            "shl	v8.2d, v10.2d, #63\n\t"
            "add	x8, x8, x13\n\t"
            "sri	v8.2d, v10.2d, #1\n\t"
            "eor	x12, x12, x7\n\t"
            "tbl	v9.16b, {v10.16b}, v11.16b\n\t"
            "add	x8, x8, x15\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x17, x17, x10\n\t"
            "ushr	v10.2d, v10.2d, #7\n\t"
            "add	x8, x8, x12\n\t"
            "eor	v9.16b, v9.16b, v10.16b\n\t"
            "add	x14, x14, x17\n\t"
            "add	v1.2d, v1.2d, v9.2d\n\t"
            "add	x4, x4, x8\n\t"
            "add	x8, x8, x14\n\t"
            /* Round 4 */
            "mov	x13, v2.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x4, #14\n\t"
            "ror	x14, x8, #28\n\t"
            "eor	x12, x12, x4, ror 18\n\t"
            "eor	x14, x14, x8, ror 34\n\t"
            "eor	x12, x12, x4, ror 41\n\t"
            "eor	x14, x14, x8, ror 39\n\t"
            "add	x7, x7, x12\n\t"
            "eor	x17, x8, x9\n\t"
            "eor	x12, x5, x6\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x4\n\t"
            "add	x7, x7, x13\n\t"
            "eor	x12, x12, x6\n\t"
            "add	x7, x7, x15\n\t"
            "eor	x16, x16, x9\n\t"
            "add	x7, x7, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x11, x11, x7\n\t"
            "add	x7, x7, x14\n\t"
            /* Round 5 */
            "mov	x13, v2.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ext	v10.16b, v2.16b, v3.16b, #8\n\t"
            "ror	x12, x11, #14\n\t"
            "shl	v8.2d, v1.2d, #45\n\t"
            "ror	x14, x7, #28\n\t"
            "sri	v8.2d, v1.2d, #19\n\t"
            "eor	x12, x12, x11, ror 18\n\t"
            "shl	v9.2d, v1.2d, #3\n\t"
            "eor	x14, x14, x7, ror 34\n\t"
            "sri	v9.2d, v1.2d, #61\n\t"
            "eor	x12, x12, x11, ror 41\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x14, x14, x7, ror 39\n\t"
            "ushr	v8.2d, v1.2d, #6\n\t"
            "add	x6, x6, x12\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x16, x7, x8\n\t"
            "add	v2.2d, v2.2d, v9.2d\n\t"
            "eor	x12, x4, x5\n\t"
            "ext	v9.16b, v6.16b, v7.16b, #8\n\t"
            "and	x17, x16, x17\n\t"
            "add	v2.2d, v2.2d, v9.2d\n\t"
            "and	x12, x12, x11\n\t"
            "shl	v8.2d, v10.2d, #63\n\t"
            "add	x6, x6, x13\n\t"
            "sri	v8.2d, v10.2d, #1\n\t"
            "eor	x12, x12, x5\n\t"
            "tbl	v9.16b, {v10.16b}, v11.16b\n\t"
            "add	x6, x6, x15\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x17, x17, x8\n\t"
            "ushr	v10.2d, v10.2d, #7\n\t"
            "add	x6, x6, x12\n\t"
            "eor	v9.16b, v9.16b, v10.16b\n\t"
            "add	x14, x14, x17\n\t"
            "add	v2.2d, v2.2d, v9.2d\n\t"
            "add	x10, x10, x6\n\t"
            "add	x6, x6, x14\n\t"
            /* Round 6 */
            "mov	x13, v3.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x10, #14\n\t"
            "ror	x14, x6, #28\n\t"
            "eor	x12, x12, x10, ror 18\n\t"
            "eor	x14, x14, x6, ror 34\n\t"
            "eor	x12, x12, x10, ror 41\n\t"
            "eor	x14, x14, x6, ror 39\n\t"
            "add	x5, x5, x12\n\t"
            "eor	x17, x6, x7\n\t"
            "eor	x12, x11, x4\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x10\n\t"
            "add	x5, x5, x13\n\t"
            "eor	x12, x12, x4\n\t"
            "add	x5, x5, x15\n\t"
            "eor	x16, x16, x7\n\t"
            "add	x5, x5, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x9, x9, x5\n\t"
            "add	x5, x5, x14\n\t"
            /* Round 7 */
            "mov	x13, v3.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ext	v10.16b, v3.16b, v4.16b, #8\n\t"
            "ror	x12, x9, #14\n\t"
            "shl	v8.2d, v2.2d, #45\n\t"
            "ror	x14, x5, #28\n\t"
            "sri	v8.2d, v2.2d, #19\n\t"
            "eor	x12, x12, x9, ror 18\n\t"
            "shl	v9.2d, v2.2d, #3\n\t"
            "eor	x14, x14, x5, ror 34\n\t"
            "sri	v9.2d, v2.2d, #61\n\t"
            "eor	x12, x12, x9, ror 41\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x14, x14, x5, ror 39\n\t"
            "ushr	v8.2d, v2.2d, #6\n\t"
            "add	x4, x4, x12\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x16, x5, x6\n\t"
            "add	v3.2d, v3.2d, v9.2d\n\t"
            "eor	x12, x10, x11\n\t"
            "ext	v9.16b, v7.16b, v0.16b, #8\n\t"
            "and	x17, x16, x17\n\t"
            "add	v3.2d, v3.2d, v9.2d\n\t"
            "and	x12, x12, x9\n\t"
            "shl	v8.2d, v10.2d, #63\n\t"
            "add	x4, x4, x13\n\t"
            "sri	v8.2d, v10.2d, #1\n\t"
            "eor	x12, x12, x11\n\t"
            "tbl	v9.16b, {v10.16b}, v11.16b\n\t"
            "add	x4, x4, x15\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x17, x17, x6\n\t"
            "ushr	v10.2d, v10.2d, #7\n\t"
            "add	x4, x4, x12\n\t"
            "eor	v9.16b, v9.16b, v10.16b\n\t"
            "add	x14, x14, x17\n\t"
            "add	v3.2d, v3.2d, v9.2d\n\t"
            "add	x8, x8, x4\n\t"
            "add	x4, x4, x14\n\t"
            /* Round 8 */
            "mov	x13, v4.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x8, #14\n\t"
            "ror	x14, x4, #28\n\t"
            "eor	x12, x12, x8, ror 18\n\t"
            "eor	x14, x14, x4, ror 34\n\t"
            "eor	x12, x12, x8, ror 41\n\t"
            "eor	x14, x14, x4, ror 39\n\t"
            "add	x11, x11, x12\n\t"
            "eor	x17, x4, x5\n\t"
            "eor	x12, x9, x10\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x8\n\t"
            "add	x11, x11, x13\n\t"
            "eor	x12, x12, x10\n\t"
            "add	x11, x11, x15\n\t"
            "eor	x16, x16, x5\n\t"
            "add	x11, x11, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x7, x7, x11\n\t"
            "add	x11, x11, x14\n\t"
            /* Round 9 */
            "mov	x13, v4.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ext	v10.16b, v4.16b, v5.16b, #8\n\t"
            "ror	x12, x7, #14\n\t"
            "shl	v8.2d, v3.2d, #45\n\t"
            "ror	x14, x11, #28\n\t"
            "sri	v8.2d, v3.2d, #19\n\t"
            "eor	x12, x12, x7, ror 18\n\t"
            "shl	v9.2d, v3.2d, #3\n\t"
            "eor	x14, x14, x11, ror 34\n\t"
            "sri	v9.2d, v3.2d, #61\n\t"
            "eor	x12, x12, x7, ror 41\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x14, x14, x11, ror 39\n\t"
            "ushr	v8.2d, v3.2d, #6\n\t"
            "add	x10, x10, x12\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x16, x11, x4\n\t"
            "add	v4.2d, v4.2d, v9.2d\n\t"
            "eor	x12, x8, x9\n\t"
            "ext	v9.16b, v0.16b, v1.16b, #8\n\t"
            "and	x17, x16, x17\n\t"
            "add	v4.2d, v4.2d, v9.2d\n\t"
            "and	x12, x12, x7\n\t"
            "shl	v8.2d, v10.2d, #63\n\t"
            "add	x10, x10, x13\n\t"
            "sri	v8.2d, v10.2d, #1\n\t"
            "eor	x12, x12, x9\n\t"
            "tbl	v9.16b, {v10.16b}, v11.16b\n\t"
            "add	x10, x10, x15\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x17, x17, x4\n\t"
            "ushr	v10.2d, v10.2d, #7\n\t"
            "add	x10, x10, x12\n\t"
            "eor	v9.16b, v9.16b, v10.16b\n\t"
            "add	x14, x14, x17\n\t"
            "add	v4.2d, v4.2d, v9.2d\n\t"
            "add	x6, x6, x10\n\t"
            "add	x10, x10, x14\n\t"
            /* Round 10 */
            "mov	x13, v5.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x6, #14\n\t"
            "ror	x14, x10, #28\n\t"
            "eor	x12, x12, x6, ror 18\n\t"
            "eor	x14, x14, x10, ror 34\n\t"
            "eor	x12, x12, x6, ror 41\n\t"
            "eor	x14, x14, x10, ror 39\n\t"
            "add	x9, x9, x12\n\t"
            "eor	x17, x10, x11\n\t"
            "eor	x12, x7, x8\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x6\n\t"
            "add	x9, x9, x13\n\t"
            "eor	x12, x12, x8\n\t"
            "add	x9, x9, x15\n\t"
            "eor	x16, x16, x11\n\t"
            "add	x9, x9, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x5, x5, x9\n\t"
            "add	x9, x9, x14\n\t"
            /* Round 11 */
            "mov	x13, v5.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ext	v10.16b, v5.16b, v6.16b, #8\n\t"
            "ror	x12, x5, #14\n\t"
            "shl	v8.2d, v4.2d, #45\n\t"
            "ror	x14, x9, #28\n\t"
            "sri	v8.2d, v4.2d, #19\n\t"
            "eor	x12, x12, x5, ror 18\n\t"
            "shl	v9.2d, v4.2d, #3\n\t"
            "eor	x14, x14, x9, ror 34\n\t"
            "sri	v9.2d, v4.2d, #61\n\t"
            "eor	x12, x12, x5, ror 41\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x14, x14, x9, ror 39\n\t"
            "ushr	v8.2d, v4.2d, #6\n\t"
            "add	x8, x8, x12\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x16, x9, x10\n\t"
            "add	v5.2d, v5.2d, v9.2d\n\t"
            "eor	x12, x6, x7\n\t"
            "ext	v9.16b, v1.16b, v2.16b, #8\n\t"
            "and	x17, x16, x17\n\t"
            "add	v5.2d, v5.2d, v9.2d\n\t"
            "and	x12, x12, x5\n\t"
            "shl	v8.2d, v10.2d, #63\n\t"
            "add	x8, x8, x13\n\t"
            "sri	v8.2d, v10.2d, #1\n\t"
            "eor	x12, x12, x7\n\t"
            "tbl	v9.16b, {v10.16b}, v11.16b\n\t"
            "add	x8, x8, x15\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x17, x17, x10\n\t"
            "ushr	v10.2d, v10.2d, #7\n\t"
            "add	x8, x8, x12\n\t"
            "eor	v9.16b, v9.16b, v10.16b\n\t"
            "add	x14, x14, x17\n\t"
            "add	v5.2d, v5.2d, v9.2d\n\t"
            "add	x4, x4, x8\n\t"
            "add	x8, x8, x14\n\t"
            /* Round 12 */
            "mov	x13, v6.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x4, #14\n\t"
            "ror	x14, x8, #28\n\t"
            "eor	x12, x12, x4, ror 18\n\t"
            "eor	x14, x14, x8, ror 34\n\t"
            "eor	x12, x12, x4, ror 41\n\t"
            "eor	x14, x14, x8, ror 39\n\t"
            "add	x7, x7, x12\n\t"
            "eor	x17, x8, x9\n\t"
            "eor	x12, x5, x6\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x4\n\t"
            "add	x7, x7, x13\n\t"
            "eor	x12, x12, x6\n\t"
            "add	x7, x7, x15\n\t"
            "eor	x16, x16, x9\n\t"
            "add	x7, x7, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x11, x11, x7\n\t"
            "add	x7, x7, x14\n\t"
            /* Round 13 */
            "mov	x13, v6.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ext	v10.16b, v6.16b, v7.16b, #8\n\t"
            "ror	x12, x11, #14\n\t"
            "shl	v8.2d, v5.2d, #45\n\t"
            "ror	x14, x7, #28\n\t"
            "sri	v8.2d, v5.2d, #19\n\t"
            "eor	x12, x12, x11, ror 18\n\t"
            "shl	v9.2d, v5.2d, #3\n\t"
            "eor	x14, x14, x7, ror 34\n\t"
            "sri	v9.2d, v5.2d, #61\n\t"
            "eor	x12, x12, x11, ror 41\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x14, x14, x7, ror 39\n\t"
            "ushr	v8.2d, v5.2d, #6\n\t"
            "add	x6, x6, x12\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x16, x7, x8\n\t"
            "add	v6.2d, v6.2d, v9.2d\n\t"
            "eor	x12, x4, x5\n\t"
            "ext	v9.16b, v2.16b, v3.16b, #8\n\t"
            "and	x17, x16, x17\n\t"
            "add	v6.2d, v6.2d, v9.2d\n\t"
            "and	x12, x12, x11\n\t"
            "shl	v8.2d, v10.2d, #63\n\t"
            "add	x6, x6, x13\n\t"
            "sri	v8.2d, v10.2d, #1\n\t"
            "eor	x12, x12, x5\n\t"
            "tbl	v9.16b, {v10.16b}, v11.16b\n\t"
            "add	x6, x6, x15\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x17, x17, x8\n\t"
            "ushr	v10.2d, v10.2d, #7\n\t"
            "add	x6, x6, x12\n\t"
            "eor	v9.16b, v9.16b, v10.16b\n\t"
            "add	x14, x14, x17\n\t"
            "add	v6.2d, v6.2d, v9.2d\n\t"
            "add	x10, x10, x6\n\t"
            "add	x6, x6, x14\n\t"
            /* Round 14 */
            "mov	x13, v7.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x10, #14\n\t"
            "ror	x14, x6, #28\n\t"
            "eor	x12, x12, x10, ror 18\n\t"
            "eor	x14, x14, x6, ror 34\n\t"
            "eor	x12, x12, x10, ror 41\n\t"
            "eor	x14, x14, x6, ror 39\n\t"
            "add	x5, x5, x12\n\t"
            "eor	x17, x6, x7\n\t"
            "eor	x12, x11, x4\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x10\n\t"
            "add	x5, x5, x13\n\t"
            "eor	x12, x12, x4\n\t"
            "add	x5, x5, x15\n\t"
            "eor	x16, x16, x7\n\t"
            "add	x5, x5, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x9, x9, x5\n\t"
            "add	x5, x5, x14\n\t"
            /* Round 15 */
            "mov	x13, v7.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ext	v10.16b, v7.16b, v0.16b, #8\n\t"
            "ror	x12, x9, #14\n\t"
            "shl	v8.2d, v6.2d, #45\n\t"
            "ror	x14, x5, #28\n\t"
            "sri	v8.2d, v6.2d, #19\n\t"
            "eor	x12, x12, x9, ror 18\n\t"
            "shl	v9.2d, v6.2d, #3\n\t"
            "eor	x14, x14, x5, ror 34\n\t"
            "sri	v9.2d, v6.2d, #61\n\t"
            "eor	x12, x12, x9, ror 41\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x14, x14, x5, ror 39\n\t"
            "ushr	v8.2d, v6.2d, #6\n\t"
            "add	x4, x4, x12\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x16, x5, x6\n\t"
            "add	v7.2d, v7.2d, v9.2d\n\t"
            "eor	x12, x10, x11\n\t"
            "ext	v9.16b, v3.16b, v4.16b, #8\n\t"
            "and	x17, x16, x17\n\t"
            "add	v7.2d, v7.2d, v9.2d\n\t"
            "and	x12, x12, x9\n\t"
            "shl	v8.2d, v10.2d, #63\n\t"
            "add	x4, x4, x13\n\t"
            "sri	v8.2d, v10.2d, #1\n\t"
            "eor	x12, x12, x11\n\t"
            "tbl	v9.16b, {v10.16b}, v11.16b\n\t"
            "add	x4, x4, x15\n\t"
            "eor	v9.16b, v9.16b, v8.16b\n\t"
            "eor	x17, x17, x6\n\t"
            "ushr	v10.2d, v10.2d, #7\n\t"
            "add	x4, x4, x12\n\t"
            "eor	v9.16b, v9.16b, v10.16b\n\t"
            "add	x14, x14, x17\n\t"
            "add	v7.2d, v7.2d, v9.2d\n\t"
            "add	x8, x8, x4\n\t"
            "add	x4, x4, x14\n\t"
            "subs	x27, x27, #1\n\t"
            "bne	L_sha512_len_neon_start_%=\n\t"
            /* Round 0 */
            "mov	x13, v0.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x8, #14\n\t"
            "ror	x14, x4, #28\n\t"
            "eor	x12, x12, x8, ror 18\n\t"
            "eor	x14, x14, x4, ror 34\n\t"
            "eor	x12, x12, x8, ror 41\n\t"
            "eor	x14, x14, x4, ror 39\n\t"
            "add	x11, x11, x12\n\t"
            "eor	x17, x4, x5\n\t"
            "eor	x12, x9, x10\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x8\n\t"
            "add	x11, x11, x13\n\t"
            "eor	x12, x12, x10\n\t"
            "add	x11, x11, x15\n\t"
            "eor	x16, x16, x5\n\t"
            "add	x11, x11, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x7, x7, x11\n\t"
            "add	x11, x11, x14\n\t"
            /* Round 1 */
            "mov	x13, v0.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x7, #14\n\t"
            "ror	x14, x11, #28\n\t"
            "eor	x12, x12, x7, ror 18\n\t"
            "eor	x14, x14, x11, ror 34\n\t"
            "eor	x12, x12, x7, ror 41\n\t"
            "eor	x14, x14, x11, ror 39\n\t"
            "add	x10, x10, x12\n\t"
            "eor	x16, x11, x4\n\t"
            "eor	x12, x8, x9\n\t"
            "and	x17, x16, x17\n\t"
            "and	x12, x12, x7\n\t"
            "add	x10, x10, x13\n\t"
            "eor	x12, x12, x9\n\t"
            "add	x10, x10, x15\n\t"
            "eor	x17, x17, x4\n\t"
            "add	x10, x10, x12\n\t"
            "add	x14, x14, x17\n\t"
            "add	x6, x6, x10\n\t"
            "add	x10, x10, x14\n\t"
            /* Round 2 */
            "mov	x13, v1.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x6, #14\n\t"
            "ror	x14, x10, #28\n\t"
            "eor	x12, x12, x6, ror 18\n\t"
            "eor	x14, x14, x10, ror 34\n\t"
            "eor	x12, x12, x6, ror 41\n\t"
            "eor	x14, x14, x10, ror 39\n\t"
            "add	x9, x9, x12\n\t"
            "eor	x17, x10, x11\n\t"
            "eor	x12, x7, x8\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x6\n\t"
            "add	x9, x9, x13\n\t"
            "eor	x12, x12, x8\n\t"
            "add	x9, x9, x15\n\t"
            "eor	x16, x16, x11\n\t"
            "add	x9, x9, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x5, x5, x9\n\t"
            "add	x9, x9, x14\n\t"
            /* Round 3 */
            "mov	x13, v1.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x5, #14\n\t"
            "ror	x14, x9, #28\n\t"
            "eor	x12, x12, x5, ror 18\n\t"
            "eor	x14, x14, x9, ror 34\n\t"
            "eor	x12, x12, x5, ror 41\n\t"
            "eor	x14, x14, x9, ror 39\n\t"
            "add	x8, x8, x12\n\t"
            "eor	x16, x9, x10\n\t"
            "eor	x12, x6, x7\n\t"
            "and	x17, x16, x17\n\t"
            "and	x12, x12, x5\n\t"
            "add	x8, x8, x13\n\t"
            "eor	x12, x12, x7\n\t"
            "add	x8, x8, x15\n\t"
            "eor	x17, x17, x10\n\t"
            "add	x8, x8, x12\n\t"
            "add	x14, x14, x17\n\t"
            "add	x4, x4, x8\n\t"
            "add	x8, x8, x14\n\t"
            /* Round 4 */
            "mov	x13, v2.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x4, #14\n\t"
            "ror	x14, x8, #28\n\t"
            "eor	x12, x12, x4, ror 18\n\t"
            "eor	x14, x14, x8, ror 34\n\t"
            "eor	x12, x12, x4, ror 41\n\t"
            "eor	x14, x14, x8, ror 39\n\t"
            "add	x7, x7, x12\n\t"
            "eor	x17, x8, x9\n\t"
            "eor	x12, x5, x6\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x4\n\t"
            "add	x7, x7, x13\n\t"
            "eor	x12, x12, x6\n\t"
            "add	x7, x7, x15\n\t"
            "eor	x16, x16, x9\n\t"
            "add	x7, x7, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x11, x11, x7\n\t"
            "add	x7, x7, x14\n\t"
            /* Round 5 */
            "mov	x13, v2.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x11, #14\n\t"
            "ror	x14, x7, #28\n\t"
            "eor	x12, x12, x11, ror 18\n\t"
            "eor	x14, x14, x7, ror 34\n\t"
            "eor	x12, x12, x11, ror 41\n\t"
            "eor	x14, x14, x7, ror 39\n\t"
            "add	x6, x6, x12\n\t"
            "eor	x16, x7, x8\n\t"
            "eor	x12, x4, x5\n\t"
            "and	x17, x16, x17\n\t"
            "and	x12, x12, x11\n\t"
            "add	x6, x6, x13\n\t"
            "eor	x12, x12, x5\n\t"
            "add	x6, x6, x15\n\t"
            "eor	x17, x17, x8\n\t"
            "add	x6, x6, x12\n\t"
            "add	x14, x14, x17\n\t"
            "add	x10, x10, x6\n\t"
            "add	x6, x6, x14\n\t"
            /* Round 6 */
            "mov	x13, v3.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x10, #14\n\t"
            "ror	x14, x6, #28\n\t"
            "eor	x12, x12, x10, ror 18\n\t"
            "eor	x14, x14, x6, ror 34\n\t"
            "eor	x12, x12, x10, ror 41\n\t"
            "eor	x14, x14, x6, ror 39\n\t"
            "add	x5, x5, x12\n\t"
            "eor	x17, x6, x7\n\t"
            "eor	x12, x11, x4\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x10\n\t"
            "add	x5, x5, x13\n\t"
            "eor	x12, x12, x4\n\t"
            "add	x5, x5, x15\n\t"
            "eor	x16, x16, x7\n\t"
            "add	x5, x5, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x9, x9, x5\n\t"
            "add	x5, x5, x14\n\t"
            /* Round 7 */
            "mov	x13, v3.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x9, #14\n\t"
            "ror	x14, x5, #28\n\t"
            "eor	x12, x12, x9, ror 18\n\t"
            "eor	x14, x14, x5, ror 34\n\t"
            "eor	x12, x12, x9, ror 41\n\t"
            "eor	x14, x14, x5, ror 39\n\t"
            "add	x4, x4, x12\n\t"
            "eor	x16, x5, x6\n\t"
            "eor	x12, x10, x11\n\t"
            "and	x17, x16, x17\n\t"
            "and	x12, x12, x9\n\t"
            "add	x4, x4, x13\n\t"
            "eor	x12, x12, x11\n\t"
            "add	x4, x4, x15\n\t"
            "eor	x17, x17, x6\n\t"
            "add	x4, x4, x12\n\t"
            "add	x14, x14, x17\n\t"
            "add	x8, x8, x4\n\t"
            "add	x4, x4, x14\n\t"
            /* Round 8 */
            "mov	x13, v4.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x8, #14\n\t"
            "ror	x14, x4, #28\n\t"
            "eor	x12, x12, x8, ror 18\n\t"
            "eor	x14, x14, x4, ror 34\n\t"
            "eor	x12, x12, x8, ror 41\n\t"
            "eor	x14, x14, x4, ror 39\n\t"
            "add	x11, x11, x12\n\t"
            "eor	x17, x4, x5\n\t"
            "eor	x12, x9, x10\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x8\n\t"
            "add	x11, x11, x13\n\t"
            "eor	x12, x12, x10\n\t"
            "add	x11, x11, x15\n\t"
            "eor	x16, x16, x5\n\t"
            "add	x11, x11, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x7, x7, x11\n\t"
            "add	x11, x11, x14\n\t"
            /* Round 9 */
            "mov	x13, v4.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x7, #14\n\t"
            "ror	x14, x11, #28\n\t"
            "eor	x12, x12, x7, ror 18\n\t"
            "eor	x14, x14, x11, ror 34\n\t"
            "eor	x12, x12, x7, ror 41\n\t"
            "eor	x14, x14, x11, ror 39\n\t"
            "add	x10, x10, x12\n\t"
            "eor	x16, x11, x4\n\t"
            "eor	x12, x8, x9\n\t"
            "and	x17, x16, x17\n\t"
            "and	x12, x12, x7\n\t"
            "add	x10, x10, x13\n\t"
            "eor	x12, x12, x9\n\t"
            "add	x10, x10, x15\n\t"
            "eor	x17, x17, x4\n\t"
            "add	x10, x10, x12\n\t"
            "add	x14, x14, x17\n\t"
            "add	x6, x6, x10\n\t"
            "add	x10, x10, x14\n\t"
            /* Round 10 */
            "mov	x13, v5.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x6, #14\n\t"
            "ror	x14, x10, #28\n\t"
            "eor	x12, x12, x6, ror 18\n\t"
            "eor	x14, x14, x10, ror 34\n\t"
            "eor	x12, x12, x6, ror 41\n\t"
            "eor	x14, x14, x10, ror 39\n\t"
            "add	x9, x9, x12\n\t"
            "eor	x17, x10, x11\n\t"
            "eor	x12, x7, x8\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x6\n\t"
            "add	x9, x9, x13\n\t"
            "eor	x12, x12, x8\n\t"
            "add	x9, x9, x15\n\t"
            "eor	x16, x16, x11\n\t"
            "add	x9, x9, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x5, x5, x9\n\t"
            "add	x9, x9, x14\n\t"
            /* Round 11 */
            "mov	x13, v5.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x5, #14\n\t"
            "ror	x14, x9, #28\n\t"
            "eor	x12, x12, x5, ror 18\n\t"
            "eor	x14, x14, x9, ror 34\n\t"
            "eor	x12, x12, x5, ror 41\n\t"
            "eor	x14, x14, x9, ror 39\n\t"
            "add	x8, x8, x12\n\t"
            "eor	x16, x9, x10\n\t"
            "eor	x12, x6, x7\n\t"
            "and	x17, x16, x17\n\t"
            "and	x12, x12, x5\n\t"
            "add	x8, x8, x13\n\t"
            "eor	x12, x12, x7\n\t"
            "add	x8, x8, x15\n\t"
            "eor	x17, x17, x10\n\t"
            "add	x8, x8, x12\n\t"
            "add	x14, x14, x17\n\t"
            "add	x4, x4, x8\n\t"
            "add	x8, x8, x14\n\t"
            /* Round 12 */
            "mov	x13, v6.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x4, #14\n\t"
            "ror	x14, x8, #28\n\t"
            "eor	x12, x12, x4, ror 18\n\t"
            "eor	x14, x14, x8, ror 34\n\t"
            "eor	x12, x12, x4, ror 41\n\t"
            "eor	x14, x14, x8, ror 39\n\t"
            "add	x7, x7, x12\n\t"
            "eor	x17, x8, x9\n\t"
            "eor	x12, x5, x6\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x4\n\t"
            "add	x7, x7, x13\n\t"
            "eor	x12, x12, x6\n\t"
            "add	x7, x7, x15\n\t"
            "eor	x16, x16, x9\n\t"
            "add	x7, x7, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x11, x11, x7\n\t"
            "add	x7, x7, x14\n\t"
            /* Round 13 */
            "mov	x13, v6.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x11, #14\n\t"
            "ror	x14, x7, #28\n\t"
            "eor	x12, x12, x11, ror 18\n\t"
            "eor	x14, x14, x7, ror 34\n\t"
            "eor	x12, x12, x11, ror 41\n\t"
            "eor	x14, x14, x7, ror 39\n\t"
            "add	x6, x6, x12\n\t"
            "eor	x16, x7, x8\n\t"
            "eor	x12, x4, x5\n\t"
            "and	x17, x16, x17\n\t"
            "and	x12, x12, x11\n\t"
            "add	x6, x6, x13\n\t"
            "eor	x12, x12, x5\n\t"
            "add	x6, x6, x15\n\t"
            "eor	x17, x17, x8\n\t"
            "add	x6, x6, x12\n\t"
            "add	x14, x14, x17\n\t"
            "add	x10, x10, x6\n\t"
            "add	x6, x6, x14\n\t"
            /* Round 14 */
            "mov	x13, v7.d[0]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x10, #14\n\t"
            "ror	x14, x6, #28\n\t"
            "eor	x12, x12, x10, ror 18\n\t"
            "eor	x14, x14, x6, ror 34\n\t"
            "eor	x12, x12, x10, ror 41\n\t"
            "eor	x14, x14, x6, ror 39\n\t"
            "add	x5, x5, x12\n\t"
            "eor	x17, x6, x7\n\t"
            "eor	x12, x11, x4\n\t"
            "and	x16, x17, x16\n\t"
            "and	x12, x12, x10\n\t"
            "add	x5, x5, x13\n\t"
            "eor	x12, x12, x4\n\t"
            "add	x5, x5, x15\n\t"
            "eor	x16, x16, x7\n\t"
            "add	x5, x5, x12\n\t"
            "add	x14, x14, x16\n\t"
            "add	x9, x9, x5\n\t"
            "add	x5, x5, x14\n\t"
            /* Round 15 */
            "mov	x13, v7.d[1]\n\t"
            "ldr	x15, [x3], #8\n\t"
            "ror	x12, x9, #14\n\t"
            "ror	x14, x5, #28\n\t"
            "eor	x12, x12, x9, ror 18\n\t"
            "eor	x14, x14, x5, ror 34\n\t"
            "eor	x12, x12, x9, ror 41\n\t"
            "eor	x14, x14, x5, ror 39\n\t"
            "add	x4, x4, x12\n\t"
            "eor	x16, x5, x6\n\t"
            "eor	x12, x10, x11\n\t"
            "and	x17, x16, x17\n\t"
            "and	x12, x12, x9\n\t"
            "add	x4, x4, x13\n\t"
            "eor	x12, x12, x11\n\t"
            "add	x4, x4, x15\n\t"
            "eor	x17, x17, x6\n\t"
            "add	x4, x4, x12\n\t"
            "add	x14, x14, x17\n\t"
            "add	x8, x8, x4\n\t"
            "add	x4, x4, x14\n\t"
            "add	x11, x11, x26\n\t"
            "add	x10, x10, x25\n\t"
            "add	x9, x9, x24\n\t"
            "add	x8, x8, x23\n\t"
            "add	x7, x7, x22\n\t"
            "add	x6, x6, x21\n\t"
            "add	x5, x5, x20\n\t"
            "add	x4, x4, x19\n\t"
    #ifndef __APPLE__
            "adr	x3, %[L_SHA512_transform_neon_len_k]\n\t"
    #else
            "adrp	x3, %[L_SHA512_transform_neon_len_k]@PAGE\n\t"
            "add	x3, x3, %[L_SHA512_transform_neon_len_k]@PAGEOFF\n\t"
    #endif /* __APPLE__ */
            "subs	%w[len], %w[len], #0x80\n\t"
            "bne	L_sha512_len_neon_begin_%=\n\t"
            "stp	x4, x5, [%x[sha512]]\n\t"
            "stp	x6, x7, [%x[sha512], #16]\n\t"
            "stp	x8, x9, [%x[sha512], #32]\n\t"
            "stp	x10, x11, [%x[sha512], #48]\n\t"
            "ldp	x29, x30, [sp], #16\n\t"
            : [sha512] "+r" (sha512), [data] "+r" (data), [len] "+r" (len)
            : [L_SHA512_transform_neon_len_k] "S" (L_SHA512_transform_neon_len_k), [L_SHA512_transform_neon_len_ror8] "S" (L_SHA512_transform_neon_len_ror8)
            : "memory", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11"
        );
    }

    #endif /* __aarch64__ */

    /* end of: armv8-sha512-asm.c */

    /* start of: armv8-32-sha512-asm */

    /* Generated using (from wolfssl):
     *   cd ../scripts
     *   ruby ./sha2/sha512.rb arm32 ../wolfssl/wolfcrypt/src/port/arm/armv8-32-sha512-asm.c
     */

    #ifndef __aarch64__
    #include <stdint.h>

    #ifdef HAVE_CONFIG_H
        #include <config.h>
    #endif

    #include <wolfssl/wolfcrypt/settings.h>

    #ifdef WOLFSSL_ARMASM
    #include <wolfssl/wolfcrypt/sha512.h>

    #ifdef WOLFSSL_ARMASM_NO_NEON
    static const uint64_t L_SHA512_transform_len_k[] = {
        0x428a2f98d728ae22UL,
        0x7137449123ef65cdUL,
        0xb5c0fbcfec4d3b2fUL,
        0xe9b5dba58189dbbcUL,
        0x3956c25bf348b538UL,
        0x59f111f1b605d019UL,
        0x923f82a4af194f9bUL,
        0xab1c5ed5da6d8118UL,
        0xd807aa98a3030242UL,
        0x12835b0145706fbeUL,
        0x243185be4ee4b28cUL,
        0x550c7dc3d5ffb4e2UL,
        0x72be5d74f27b896fUL,
        0x80deb1fe3b1696b1UL,
        0x9bdc06a725c71235UL,
        0xc19bf174cf692694UL,
        0xe49b69c19ef14ad2UL,
        0xefbe4786384f25e3UL,
        0xfc19dc68b8cd5b5UL,
        0x240ca1cc77ac9c65UL,
        0x2de92c6f592b0275UL,
        0x4a7484aa6ea6e483UL,
        0x5cb0a9dcbd41fbd4UL,
        0x76f988da831153b5UL,
        0x983e5152ee66dfabUL,
        0xa831c66d2db43210UL,
        0xb00327c898fb213fUL,
        0xbf597fc7beef0ee4UL,
        0xc6e00bf33da88fc2UL,
        0xd5a79147930aa725UL,
        0x6ca6351e003826fUL,
        0x142929670a0e6e70UL,
        0x27b70a8546d22ffcUL,
        0x2e1b21385c26c926UL,
        0x4d2c6dfc5ac42aedUL,
        0x53380d139d95b3dfUL,
        0x650a73548baf63deUL,
        0x766a0abb3c77b2a8UL,
        0x81c2c92e47edaee6UL,
        0x92722c851482353bUL,
        0xa2bfe8a14cf10364UL,
        0xa81a664bbc423001UL,
        0xc24b8b70d0f89791UL,
        0xc76c51a30654be30UL,
        0xd192e819d6ef5218UL,
        0xd69906245565a910UL,
        0xf40e35855771202aUL,
        0x106aa07032bbd1b8UL,
        0x19a4c116b8d2d0c8UL,
        0x1e376c085141ab53UL,
        0x2748774cdf8eeb99UL,
        0x34b0bcb5e19b48a8UL,
        0x391c0cb3c5c95a63UL,
        0x4ed8aa4ae3418acbUL,
        0x5b9cca4f7763e373UL,
        0x682e6ff3d6b2b8a3UL,
        0x748f82ee5defb2fcUL,
        0x78a5636f43172f60UL,
        0x84c87814a1f0ab72UL,
        0x8cc702081a6439ecUL,
        0x90befffa23631e28UL,
        0xa4506cebde82bde9UL,
        0xbef9a3f7b2c67915UL,
        0xc67178f2e372532bUL,
        0xca273eceea26619cUL,
        0xd186b8c721c0c207UL,
        0xeada7dd6cde0eb1eUL,
        0xf57d4f7fee6ed178UL,
        0x6f067aa72176fbaUL,
        0xa637dc5a2c898a6UL,
        0x113f9804bef90daeUL,
        0x1b710b35131c471bUL,
        0x28db77f523047d84UL,
        0x32caab7b40c72493UL,
        0x3c9ebe0a15c9bebcUL,
        0x431d67c49c100d4cUL,
        0x4cc5d4becb3e42b6UL,
        0x597f299cfc657e2aUL,
        0x5fcb6fab3ad6faecUL,
        0x6c44198c4a475817UL,
    };

    void Transform_Sha512_Len(wc_Sha512* sha512, const byte* data, word32 len)
    {
        __asm__ __volatile__ (
            "sub	sp, sp, #0xc0\n\t"
            "mov	r3, %[L_SHA512_transform_len_k]\n\t"
            /* Copy digest to add in at end */
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "ldrd	r4, r5, [%[sha512], #8]\n\t"
            "ldrd	r6, r7, [%[sha512], #16]\n\t"
            "ldrd	r8, r9, [%[sha512], #24]\n\t"
            "strd	r12, lr, [sp, #128]\n\t"
            "strd	r4, r5, [sp, #136]\n\t"
            "strd	r6, r7, [sp, #144]\n\t"
            "strd	r8, r9, [sp, #152]\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "ldrd	r4, r5, [%[sha512], #40]\n\t"
            "ldrd	r6, r7, [%[sha512], #48]\n\t"
            "ldrd	r8, r9, [%[sha512], #56]\n\t"
            "strd	r12, lr, [sp, #160]\n\t"
            "strd	r4, r5, [sp, #168]\n\t"
            "strd	r6, r7, [sp, #176]\n\t"
            "strd	r8, r9, [sp, #184]\n\t"
            /* Start of loop processing a block */
            "\n"
        "L_sha512_len_neon_begin_%=: \n\t"
            /* Load, Reverse and Store W */
            "ldrd	r12, lr, [%[data]]\n\t"
            "ldrd	r4, r5, [%[data], #8]\n\t"
            "ldrd	r6, r7, [%[data], #16]\n\t"
            "ldrd	r8, r9, [%[data], #24]\n\t"
            "rev	r12, r12\n\t"
            "rev	lr, lr\n\t"
            "rev	r4, r4\n\t"
            "rev	r5, r5\n\t"
            "rev	r6, r6\n\t"
            "rev	r7, r7\n\t"
            "rev	r8, r8\n\t"
            "rev	r9, r9\n\t"
            "str	lr, [sp]\n\t"
            "str	r12, [sp, #4]\n\t"
            "str	r5, [sp, #8]\n\t"
            "str	r4, [sp, #12]\n\t"
            "str	r7, [sp, #16]\n\t"
            "str	r6, [sp, #20]\n\t"
            "str	r9, [sp, #24]\n\t"
            "str	r8, [sp, #28]\n\t"
            "ldrd	r12, lr, [%[data], #32]\n\t"
            "ldrd	r4, r5, [%[data], #40]\n\t"
            "ldrd	r6, r7, [%[data], #48]\n\t"
            "ldrd	r8, r9, [%[data], #56]\n\t"
            "rev	r12, r12\n\t"
            "rev	lr, lr\n\t"
            "rev	r4, r4\n\t"
            "rev	r5, r5\n\t"
            "rev	r6, r6\n\t"
            "rev	r7, r7\n\t"
            "rev	r8, r8\n\t"
            "rev	r9, r9\n\t"
            "str	lr, [sp, #32]\n\t"
            "str	r12, [sp, #36]\n\t"
            "str	r5, [sp, #40]\n\t"
            "str	r4, [sp, #44]\n\t"
            "str	r7, [sp, #48]\n\t"
            "str	r6, [sp, #52]\n\t"
            "str	r9, [sp, #56]\n\t"
            "str	r8, [sp, #60]\n\t"
            "ldrd	r12, lr, [%[data], #64]\n\t"
            "ldrd	r4, r5, [%[data], #72]\n\t"
            "ldrd	r6, r7, [%[data], #80]\n\t"
            "ldrd	r8, r9, [%[data], #88]\n\t"
            "rev	r12, r12\n\t"
            "rev	lr, lr\n\t"
            "rev	r4, r4\n\t"
            "rev	r5, r5\n\t"
            "rev	r6, r6\n\t"
            "rev	r7, r7\n\t"
            "rev	r8, r8\n\t"
            "rev	r9, r9\n\t"
            "str	lr, [sp, #64]\n\t"
            "str	r12, [sp, #68]\n\t"
            "str	r5, [sp, #72]\n\t"
            "str	r4, [sp, #76]\n\t"
            "str	r7, [sp, #80]\n\t"
            "str	r6, [sp, #84]\n\t"
            "str	r9, [sp, #88]\n\t"
            "str	r8, [sp, #92]\n\t"
            "ldrd	r12, lr, [%[data], #96]\n\t"
            "ldrd	r4, r5, [%[data], #104]\n\t"
            "ldrd	r6, r7, [%[data], #112]\n\t"
            "ldrd	r8, r9, [%[data], #120]\n\t"
            "rev	r12, r12\n\t"
            "rev	lr, lr\n\t"
            "rev	r4, r4\n\t"
            "rev	r5, r5\n\t"
            "rev	r6, r6\n\t"
            "rev	r7, r7\n\t"
            "rev	r8, r8\n\t"
            "rev	r9, r9\n\t"
            "str	lr, [sp, #96]\n\t"
            "str	r12, [sp, #100]\n\t"
            "str	r5, [sp, #104]\n\t"
            "str	r4, [sp, #108]\n\t"
            "str	r7, [sp, #112]\n\t"
            "str	r6, [sp, #116]\n\t"
            "str	r9, [sp, #120]\n\t"
            "str	r8, [sp, #124]\n\t"
            /* Pre-calc: b ^ c */
            "ldrd	r8, r9, [%[sha512], #8]\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "eor	r8, r8, r12\n\t"
            "eor	r9, r9, lr\n\t"
            "mov	r10, #4\n\t"
            /* Start of 16 rounds */
            "\n"
        "L_sha512_len_neon_start_%=: \n\t"
            /* Round 0 */
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #56]\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "ldrd	r4, r5, [%[sha512], #40]\n\t"
            "ldrd	r6, r7, [%[sha512], #48]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "ldrd	r6, r7, [sp]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #24]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #56]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "strd	r6, r7, [%[sha512], #24]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512]]\n\t"
            "ldrd	r4, r5, [%[sha512], #8]\n\t"
            "strd	r12, lr, [%[sha512], #56]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #56]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #56]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[0] */
            "ldrd	r12, lr, [sp, #112]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp]\n\t"
            "ldrd	r6, r7, [sp, #72]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp]\n\t"
            "ldrd	r12, lr, [sp, #8]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp]\n\t"
            /* Round 1 */
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #48]\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "ldrd	r4, r5, [%[sha512], #32]\n\t"
            "ldrd	r6, r7, [%[sha512], #40]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "ldrd	r6, r7, [sp, #8]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #8]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #16]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #48]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "strd	r6, r7, [%[sha512], #16]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #56]\n\t"
            "ldrd	r4, r5, [%[sha512]]\n\t"
            "strd	r12, lr, [%[sha512], #48]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #48]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #48]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[1] */
            "ldrd	r12, lr, [sp, #120]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #8]\n\t"
            "ldrd	r6, r7, [sp, #80]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #8]\n\t"
            "ldrd	r12, lr, [sp, #16]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #8]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #8]\n\t"
            /* Round 2 */
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #40]\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "ldrd	r4, r5, [%[sha512], #24]\n\t"
            "ldrd	r6, r7, [%[sha512], #32]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "ldrd	r6, r7, [sp, #16]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #16]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #8]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #40]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "strd	r6, r7, [%[sha512], #8]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #48]\n\t"
            "ldrd	r4, r5, [%[sha512], #56]\n\t"
            "strd	r12, lr, [%[sha512], #40]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #40]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #40]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[2] */
            "ldrd	r12, lr, [sp]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #16]\n\t"
            "ldrd	r6, r7, [sp, #88]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #16]\n\t"
            "ldrd	r12, lr, [sp, #24]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #16]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #16]\n\t"
            /* Round 3 */
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #32]\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "ldrd	r4, r5, [%[sha512], #16]\n\t"
            "ldrd	r6, r7, [%[sha512], #24]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "ldrd	r6, r7, [sp, #24]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #24]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512]]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #32]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "strd	r6, r7, [%[sha512]]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #40]\n\t"
            "ldrd	r4, r5, [%[sha512], #48]\n\t"
            "strd	r12, lr, [%[sha512], #32]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #32]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #32]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[3] */
            "ldrd	r12, lr, [sp, #8]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #24]\n\t"
            "ldrd	r6, r7, [sp, #96]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #24]\n\t"
            "ldrd	r12, lr, [sp, #32]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #24]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #24]\n\t"
            /* Round 4 */
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #24]\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "ldrd	r4, r5, [%[sha512], #8]\n\t"
            "ldrd	r6, r7, [%[sha512], #16]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "ldrd	r6, r7, [sp, #32]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #32]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #56]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #24]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "strd	r6, r7, [%[sha512], #56]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #32]\n\t"
            "ldrd	r4, r5, [%[sha512], #40]\n\t"
            "strd	r12, lr, [%[sha512], #24]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #24]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #24]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[4] */
            "ldrd	r12, lr, [sp, #16]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #32]\n\t"
            "ldrd	r6, r7, [sp, #104]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #32]\n\t"
            "ldrd	r12, lr, [sp, #40]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #32]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #32]\n\t"
            /* Round 5 */
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #16]\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "ldrd	r4, r5, [%[sha512]]\n\t"
            "ldrd	r6, r7, [%[sha512], #8]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "ldrd	r6, r7, [sp, #40]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #40]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #48]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #16]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "strd	r6, r7, [%[sha512], #48]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #24]\n\t"
            "ldrd	r4, r5, [%[sha512], #32]\n\t"
            "strd	r12, lr, [%[sha512], #16]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #16]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #16]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[5] */
            "ldrd	r12, lr, [sp, #24]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #40]\n\t"
            "ldrd	r6, r7, [sp, #112]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #40]\n\t"
            "ldrd	r12, lr, [sp, #48]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #40]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #40]\n\t"
            /* Round 6 */
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #8]\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "ldrd	r4, r5, [%[sha512], #56]\n\t"
            "ldrd	r6, r7, [%[sha512]]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "ldrd	r6, r7, [sp, #48]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #48]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #40]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #8]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "strd	r6, r7, [%[sha512], #40]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #16]\n\t"
            "ldrd	r4, r5, [%[sha512], #24]\n\t"
            "strd	r12, lr, [%[sha512], #8]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #8]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #8]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[6] */
            "ldrd	r12, lr, [sp, #32]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #48]\n\t"
            "ldrd	r6, r7, [sp, #120]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #48]\n\t"
            "ldrd	r12, lr, [sp, #56]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #48]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #48]\n\t"
            /* Round 7 */
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512]]\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "ldrd	r4, r5, [%[sha512], #48]\n\t"
            "ldrd	r6, r7, [%[sha512], #56]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "ldrd	r6, r7, [sp, #56]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #56]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #32]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512]]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "strd	r6, r7, [%[sha512], #32]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #8]\n\t"
            "ldrd	r4, r5, [%[sha512], #16]\n\t"
            "strd	r12, lr, [%[sha512]]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512]]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512]]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[7] */
            "ldrd	r12, lr, [sp, #40]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #56]\n\t"
            "ldrd	r6, r7, [sp]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #56]\n\t"
            "ldrd	r12, lr, [sp, #64]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #56]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #56]\n\t"
            /* Round 8 */
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #56]\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "ldrd	r4, r5, [%[sha512], #40]\n\t"
            "ldrd	r6, r7, [%[sha512], #48]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "ldrd	r6, r7, [sp, #64]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #64]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #24]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #56]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "strd	r6, r7, [%[sha512], #24]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512]]\n\t"
            "ldrd	r4, r5, [%[sha512], #8]\n\t"
            "strd	r12, lr, [%[sha512], #56]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #56]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #56]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[8] */
            "ldrd	r12, lr, [sp, #48]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #64]\n\t"
            "ldrd	r6, r7, [sp, #8]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #64]\n\t"
            "ldrd	r12, lr, [sp, #72]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #64]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #64]\n\t"
            /* Round 9 */
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #48]\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "ldrd	r4, r5, [%[sha512], #32]\n\t"
            "ldrd	r6, r7, [%[sha512], #40]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "ldrd	r6, r7, [sp, #72]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #72]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #16]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #48]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "strd	r6, r7, [%[sha512], #16]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #56]\n\t"
            "ldrd	r4, r5, [%[sha512]]\n\t"
            "strd	r12, lr, [%[sha512], #48]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #48]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #48]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[9] */
            "ldrd	r12, lr, [sp, #56]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #72]\n\t"
            "ldrd	r6, r7, [sp, #16]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #72]\n\t"
            "ldrd	r12, lr, [sp, #80]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #72]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #72]\n\t"
            /* Round 10 */
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #40]\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "ldrd	r4, r5, [%[sha512], #24]\n\t"
            "ldrd	r6, r7, [%[sha512], #32]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "ldrd	r6, r7, [sp, #80]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #80]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #8]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #40]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "strd	r6, r7, [%[sha512], #8]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #48]\n\t"
            "ldrd	r4, r5, [%[sha512], #56]\n\t"
            "strd	r12, lr, [%[sha512], #40]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #40]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #40]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[10] */
            "ldrd	r12, lr, [sp, #64]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #80]\n\t"
            "ldrd	r6, r7, [sp, #24]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #80]\n\t"
            "ldrd	r12, lr, [sp, #88]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #80]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #80]\n\t"
            /* Round 11 */
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #32]\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "ldrd	r4, r5, [%[sha512], #16]\n\t"
            "ldrd	r6, r7, [%[sha512], #24]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "ldrd	r6, r7, [sp, #88]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #88]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512]]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #32]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "strd	r6, r7, [%[sha512]]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #40]\n\t"
            "ldrd	r4, r5, [%[sha512], #48]\n\t"
            "strd	r12, lr, [%[sha512], #32]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #32]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #32]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[11] */
            "ldrd	r12, lr, [sp, #72]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #88]\n\t"
            "ldrd	r6, r7, [sp, #32]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #88]\n\t"
            "ldrd	r12, lr, [sp, #96]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #88]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #88]\n\t"
            /* Round 12 */
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #24]\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "ldrd	r4, r5, [%[sha512], #8]\n\t"
            "ldrd	r6, r7, [%[sha512], #16]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "ldrd	r6, r7, [sp, #96]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #96]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #56]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #24]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "strd	r6, r7, [%[sha512], #56]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #32]\n\t"
            "ldrd	r4, r5, [%[sha512], #40]\n\t"
            "strd	r12, lr, [%[sha512], #24]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #24]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #24]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[12] */
            "ldrd	r12, lr, [sp, #80]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #96]\n\t"
            "ldrd	r6, r7, [sp, #40]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #96]\n\t"
            "ldrd	r12, lr, [sp, #104]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #96]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #96]\n\t"
            /* Round 13 */
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #16]\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "ldrd	r4, r5, [%[sha512]]\n\t"
            "ldrd	r6, r7, [%[sha512], #8]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "ldrd	r6, r7, [sp, #104]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #104]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #48]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #16]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "strd	r6, r7, [%[sha512], #48]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #24]\n\t"
            "ldrd	r4, r5, [%[sha512], #32]\n\t"
            "strd	r12, lr, [%[sha512], #16]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #16]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #16]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[13] */
            "ldrd	r12, lr, [sp, #88]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #104]\n\t"
            "ldrd	r6, r7, [sp, #48]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #104]\n\t"
            "ldrd	r12, lr, [sp, #112]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #104]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #104]\n\t"
            /* Round 14 */
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #8]\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "ldrd	r4, r5, [%[sha512], #56]\n\t"
            "ldrd	r6, r7, [%[sha512]]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "ldrd	r6, r7, [sp, #112]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #112]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #40]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #8]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "strd	r6, r7, [%[sha512], #40]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #16]\n\t"
            "ldrd	r4, r5, [%[sha512], #24]\n\t"
            "strd	r12, lr, [%[sha512], #8]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #8]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #8]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[14] */
            "ldrd	r12, lr, [sp, #96]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #112]\n\t"
            "ldrd	r6, r7, [sp, #56]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #112]\n\t"
            "ldrd	r12, lr, [sp, #120]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #112]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #112]\n\t"
            /* Round 15 */
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512]]\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "ldrd	r4, r5, [%[sha512], #48]\n\t"
            "ldrd	r6, r7, [%[sha512], #56]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "ldrd	r6, r7, [sp, #120]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #120]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #32]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512]]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "strd	r6, r7, [%[sha512], #32]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #8]\n\t"
            "ldrd	r4, r5, [%[sha512], #16]\n\t"
            "strd	r12, lr, [%[sha512]]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512]]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512]]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Calc new W[15] */
            "ldrd	r12, lr, [sp, #104]\n\t"
            "lsrs	r4, r12, #19\n\t"
            "lsrs	r5, lr, #19\n\t"
            "orr	r5, r5, r12, lsl 13\n\t"
            "orr	r4, r4, lr, lsl 13\n\t"
            "lsls	r6, r12, #3\n\t"
            "lsls	r7, lr, #3\n\t"
            "orr	r7, r7, r12, lsr 29\n\t"
            "orr	r6, r6, lr, lsr 29\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #6\n\t"
            "lsrs	r7, lr, #6\n\t"
            "orr	r6, r6, lr, lsl 26\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #120]\n\t"
            "ldrd	r6, r7, [sp, #64]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "strd	r12, lr, [sp, #120]\n\t"
            "ldrd	r12, lr, [sp]\n\t"
            "lsrs	r4, r12, #1\n\t"
            "lsrs	r5, lr, #1\n\t"
            "orr	r5, r5, r12, lsl 31\n\t"
            "orr	r4, r4, lr, lsl 31\n\t"
            "lsrs	r6, r12, #8\n\t"
            "lsrs	r7, lr, #8\n\t"
            "orr	r7, r7, r12, lsl 24\n\t"
            "orr	r6, r6, lr, lsl 24\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "lsrs	r6, r12, #7\n\t"
            "lsrs	r7, lr, #7\n\t"
            "orr	r6, r6, lr, lsl 25\n\t"
            "eor	r5, r5, r7\n\t"
            "eor	r4, r4, r6\n\t"
            "ldrd	r12, lr, [sp, #120]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [sp, #120]\n\t"
            "add	r3, r3, #0x80\n\t"
            "subs	r10, r10, #1\n\t"
            "bne	L_sha512_len_neon_start_%=\n\t"
            /* Round 0 */
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #56]\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "ldrd	r4, r5, [%[sha512], #40]\n\t"
            "ldrd	r6, r7, [%[sha512], #48]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "ldrd	r6, r7, [sp]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #24]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #56]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "strd	r6, r7, [%[sha512], #24]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512]]\n\t"
            "ldrd	r4, r5, [%[sha512], #8]\n\t"
            "strd	r12, lr, [%[sha512], #56]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #56]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #56]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 1 */
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #48]\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "ldrd	r4, r5, [%[sha512], #32]\n\t"
            "ldrd	r6, r7, [%[sha512], #40]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "ldrd	r6, r7, [sp, #8]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #8]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #16]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #48]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "strd	r6, r7, [%[sha512], #16]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #56]\n\t"
            "ldrd	r4, r5, [%[sha512]]\n\t"
            "strd	r12, lr, [%[sha512], #48]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #48]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #48]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 2 */
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #40]\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "ldrd	r4, r5, [%[sha512], #24]\n\t"
            "ldrd	r6, r7, [%[sha512], #32]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "ldrd	r6, r7, [sp, #16]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #16]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #8]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #40]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "strd	r6, r7, [%[sha512], #8]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #48]\n\t"
            "ldrd	r4, r5, [%[sha512], #56]\n\t"
            "strd	r12, lr, [%[sha512], #40]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #40]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #40]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 3 */
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #32]\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "ldrd	r4, r5, [%[sha512], #16]\n\t"
            "ldrd	r6, r7, [%[sha512], #24]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "ldrd	r6, r7, [sp, #24]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #24]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512]]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #32]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "strd	r6, r7, [%[sha512]]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #40]\n\t"
            "ldrd	r4, r5, [%[sha512], #48]\n\t"
            "strd	r12, lr, [%[sha512], #32]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #32]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #32]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 4 */
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #24]\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "ldrd	r4, r5, [%[sha512], #8]\n\t"
            "ldrd	r6, r7, [%[sha512], #16]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "ldrd	r6, r7, [sp, #32]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #32]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #56]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #24]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "strd	r6, r7, [%[sha512], #56]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #32]\n\t"
            "ldrd	r4, r5, [%[sha512], #40]\n\t"
            "strd	r12, lr, [%[sha512], #24]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #24]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #24]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 5 */
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #16]\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "ldrd	r4, r5, [%[sha512]]\n\t"
            "ldrd	r6, r7, [%[sha512], #8]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "ldrd	r6, r7, [sp, #40]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #40]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #48]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #16]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "strd	r6, r7, [%[sha512], #48]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #24]\n\t"
            "ldrd	r4, r5, [%[sha512], #32]\n\t"
            "strd	r12, lr, [%[sha512], #16]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #16]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #16]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 6 */
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #8]\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "ldrd	r4, r5, [%[sha512], #56]\n\t"
            "ldrd	r6, r7, [%[sha512]]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "ldrd	r6, r7, [sp, #48]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #48]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #40]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #8]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "strd	r6, r7, [%[sha512], #40]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #16]\n\t"
            "ldrd	r4, r5, [%[sha512], #24]\n\t"
            "strd	r12, lr, [%[sha512], #8]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #8]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #8]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 7 */
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512]]\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "ldrd	r4, r5, [%[sha512], #48]\n\t"
            "ldrd	r6, r7, [%[sha512], #56]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "ldrd	r6, r7, [sp, #56]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #56]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #32]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512]]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "strd	r6, r7, [%[sha512], #32]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #8]\n\t"
            "ldrd	r4, r5, [%[sha512], #16]\n\t"
            "strd	r12, lr, [%[sha512]]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512]]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512]]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 8 */
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #56]\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "ldrd	r4, r5, [%[sha512], #40]\n\t"
            "ldrd	r6, r7, [%[sha512], #48]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "ldrd	r6, r7, [sp, #64]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #64]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #24]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #56]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "strd	r6, r7, [%[sha512], #24]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512]]\n\t"
            "ldrd	r4, r5, [%[sha512], #8]\n\t"
            "strd	r12, lr, [%[sha512], #56]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #56]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #56]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 9 */
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #48]\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "ldrd	r4, r5, [%[sha512], #32]\n\t"
            "ldrd	r6, r7, [%[sha512], #40]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "ldrd	r6, r7, [sp, #72]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #72]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #16]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #48]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "strd	r6, r7, [%[sha512], #16]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #56]\n\t"
            "ldrd	r4, r5, [%[sha512]]\n\t"
            "strd	r12, lr, [%[sha512], #48]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #48]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #48]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 10 */
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #40]\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "ldrd	r4, r5, [%[sha512], #24]\n\t"
            "ldrd	r6, r7, [%[sha512], #32]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "ldrd	r6, r7, [sp, #80]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #80]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #8]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #40]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "strd	r6, r7, [%[sha512], #8]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #48]\n\t"
            "ldrd	r4, r5, [%[sha512], #56]\n\t"
            "strd	r12, lr, [%[sha512], #40]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #40]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #40]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 11 */
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #32]\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "ldrd	r4, r5, [%[sha512], #16]\n\t"
            "ldrd	r6, r7, [%[sha512], #24]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "ldrd	r6, r7, [sp, #88]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #88]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512]]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #32]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "strd	r6, r7, [%[sha512]]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #40]\n\t"
            "ldrd	r4, r5, [%[sha512], #48]\n\t"
            "strd	r12, lr, [%[sha512], #32]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #32]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #32]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 12 */
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #24]\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "ldrd	r4, r5, [%[sha512], #8]\n\t"
            "ldrd	r6, r7, [%[sha512], #16]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "ldrd	r6, r7, [sp, #96]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #96]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #56]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #24]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "strd	r6, r7, [%[sha512], #56]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #32]\n\t"
            "ldrd	r4, r5, [%[sha512], #40]\n\t"
            "strd	r12, lr, [%[sha512], #24]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #24]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #24]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 13 */
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #16]\n\t"
            "ldrd	r12, lr, [%[sha512], #56]\n\t"
            "ldrd	r4, r5, [%[sha512]]\n\t"
            "ldrd	r6, r7, [%[sha512], #8]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "ldrd	r6, r7, [sp, #104]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #104]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #48]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #16]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #24]\n\t"
            "strd	r6, r7, [%[sha512], #48]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #24]\n\t"
            "ldrd	r4, r5, [%[sha512], #32]\n\t"
            "strd	r12, lr, [%[sha512], #16]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #16]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #16]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 14 */
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #8]\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "ldrd	r4, r5, [%[sha512], #56]\n\t"
            "ldrd	r6, r7, [%[sha512]]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "ldrd	r6, r7, [sp, #112]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #112]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #40]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512], #8]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "strd	r6, r7, [%[sha512], #40]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #16]\n\t"
            "ldrd	r4, r5, [%[sha512], #24]\n\t"
            "strd	r12, lr, [%[sha512], #8]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512], #8]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512], #8]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Round 15 */
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "lsrs	r4, r12, #14\n\t"
            "lsrs	r5, lr, #14\n\t"
            "orr	r5, r5, r12, lsl 18\n\t"
            "orr	r4, r4, lr, lsl 18\n\t"
            "lsrs	r6, r12, #18\n\t"
            "lsrs	r7, lr, #18\n\t"
            "orr	r7, r7, r12, lsl 14\n\t"
            "orr	r6, r6, lr, lsl 14\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #23\n\t"
            "lsls	r7, lr, #23\n\t"
            "orr	r7, r7, r12, lsr 9\n\t"
            "orr	r6, r6, lr, lsr 9\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512]]\n\t"
            "ldrd	r12, lr, [%[sha512], #40]\n\t"
            "ldrd	r4, r5, [%[sha512], #48]\n\t"
            "ldrd	r6, r7, [%[sha512], #56]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "and	r4, r4, r12\n\t"
            "and	r5, r5, lr\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "ldrd	r6, r7, [sp, #120]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r4, r5, [r3, #120]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "ldrd	r6, r7, [%[sha512], #32]\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "strd	r12, lr, [%[sha512]]\n\t"
            "adds	r6, r6, r12\n\t"
            "adc	r7, r7, lr\n\t"
            "ldrd	r12, lr, [%[sha512], #8]\n\t"
            "strd	r6, r7, [%[sha512], #32]\n\t"
            "lsrs	r4, r12, #28\n\t"
            "lsrs	r5, lr, #28\n\t"
            "orr	r5, r5, r12, lsl 4\n\t"
            "orr	r4, r4, lr, lsl 4\n\t"
            "lsls	r6, r12, #30\n\t"
            "lsls	r7, lr, #30\n\t"
            "orr	r7, r7, r12, lsr 2\n\t"
            "orr	r6, r6, lr, lsr 2\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "lsls	r6, r12, #25\n\t"
            "lsls	r7, lr, #25\n\t"
            "orr	r7, r7, r12, lsr 7\n\t"
            "orr	r6, r6, lr, lsr 7\n\t"
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "eor	r4, r4, r6\n\t"
            "eor	r5, r5, r7\n\t"
            "adds	r12, r12, r4\n\t"
            "adc	lr, lr, r5\n\t"
            "ldrd	r6, r7, [%[sha512], #8]\n\t"
            "ldrd	r4, r5, [%[sha512], #16]\n\t"
            "strd	r12, lr, [%[sha512]]\n\t"
            "eor	r6, r6, r4\n\t"
            "eor	r7, r7, r5\n\t"
            "and	r8, r8, r6\n\t"
            "and	r9, r9, r7\n\t"
            "eor	r8, r8, r4\n\t"
            "eor	r9, r9, r5\n\t"
            "ldrd	r4, r5, [%[sha512]]\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r4, r5, [%[sha512]]\n\t"
            "mov	r8, r6\n\t"
            "mov	r9, r7\n\t"
            /* Add in digest from start */
            "ldrd	r12, lr, [%[sha512]]\n\t"
            "ldrd	r4, r5, [%[sha512], #8]\n\t"
            "ldrd	r6, r7, [sp, #128]\n\t"
            "ldrd	r8, r9, [sp, #136]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r12, lr, [%[sha512]]\n\t"
            "strd	r4, r5, [%[sha512], #8]\n\t"
            "strd	r12, lr, [sp, #128]\n\t"
            "strd	r4, r5, [sp, #136]\n\t"
            "ldrd	r12, lr, [%[sha512], #16]\n\t"
            "ldrd	r4, r5, [%[sha512], #24]\n\t"
            "ldrd	r6, r7, [sp, #144]\n\t"
            "ldrd	r8, r9, [sp, #152]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r12, lr, [%[sha512], #16]\n\t"
            "strd	r4, r5, [%[sha512], #24]\n\t"
            "strd	r12, lr, [sp, #144]\n\t"
            "strd	r4, r5, [sp, #152]\n\t"
            "ldrd	r12, lr, [%[sha512], #32]\n\t"
            "ldrd	r4, r5, [%[sha512], #40]\n\t"
            "ldrd	r6, r7, [sp, #160]\n\t"
            "ldrd	r8, r9, [sp, #168]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r12, lr, [%[sha512], #32]\n\t"
            "strd	r4, r5, [%[sha512], #40]\n\t"
            "strd	r12, lr, [sp, #160]\n\t"
            "strd	r4, r5, [sp, #168]\n\t"
            "ldrd	r12, lr, [%[sha512], #48]\n\t"
            "ldrd	r4, r5, [%[sha512], #56]\n\t"
            "ldrd	r6, r7, [sp, #176]\n\t"
            "ldrd	r8, r9, [sp, #184]\n\t"
            "adds	r12, r12, r6\n\t"
            "adc	lr, lr, r7\n\t"
            "adds	r4, r4, r8\n\t"
            "adc	r5, r5, r9\n\t"
            "strd	r12, lr, [%[sha512], #48]\n\t"
            "strd	r4, r5, [%[sha512], #56]\n\t"
            "strd	r12, lr, [sp, #176]\n\t"
            "strd	r4, r5, [sp, #184]\n\t"
            "subs	%[len], %[len], #0x80\n\t"
            "sub	r3, r3, #0x200\n\t"
            "add	%[data], %[data], #0x80\n\t"
            "bne	L_sha512_len_neon_begin_%=\n\t"
            "eor	r0, r0, r0\n\t"
            "add	sp, sp, #0xc0\n\t"
            : [sha512] "+r" (sha512), [data] "+r" (data), [len] "+r" (len)
            : [L_SHA512_transform_len_k] "r" (L_SHA512_transform_len_k)
            : "memory", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
        );
    }

    #endif /* WOLFSSL_ARMASM_NO_NEON */

    #include <wolfssl/wolfcrypt/sha512.h>

    void Transform_Sha512_Len(wc_Sha512* sha512, const byte* data, word32 len);

    #ifndef WOLFSSL_ARMASM_NO_NEON
    static const uint64_t L_SHA512_transform_neon_len_k[] = {
        0x428a2f98d728ae22UL,
        0x7137449123ef65cdUL,
        0xb5c0fbcfec4d3b2fUL,
        0xe9b5dba58189dbbcUL,
        0x3956c25bf348b538UL,
        0x59f111f1b605d019UL,
        0x923f82a4af194f9bUL,
        0xab1c5ed5da6d8118UL,
        0xd807aa98a3030242UL,
        0x12835b0145706fbeUL,
        0x243185be4ee4b28cUL,
        0x550c7dc3d5ffb4e2UL,
        0x72be5d74f27b896fUL,
        0x80deb1fe3b1696b1UL,
        0x9bdc06a725c71235UL,
        0xc19bf174cf692694UL,
        0xe49b69c19ef14ad2UL,
        0xefbe4786384f25e3UL,
        0xfc19dc68b8cd5b5UL,
        0x240ca1cc77ac9c65UL,
        0x2de92c6f592b0275UL,
        0x4a7484aa6ea6e483UL,
        0x5cb0a9dcbd41fbd4UL,
        0x76f988da831153b5UL,
        0x983e5152ee66dfabUL,
        0xa831c66d2db43210UL,
        0xb00327c898fb213fUL,
        0xbf597fc7beef0ee4UL,
        0xc6e00bf33da88fc2UL,
        0xd5a79147930aa725UL,
        0x6ca6351e003826fUL,
        0x142929670a0e6e70UL,
        0x27b70a8546d22ffcUL,
        0x2e1b21385c26c926UL,
        0x4d2c6dfc5ac42aedUL,
        0x53380d139d95b3dfUL,
        0x650a73548baf63deUL,
        0x766a0abb3c77b2a8UL,
        0x81c2c92e47edaee6UL,
        0x92722c851482353bUL,
        0xa2bfe8a14cf10364UL,
        0xa81a664bbc423001UL,
        0xc24b8b70d0f89791UL,
        0xc76c51a30654be30UL,
        0xd192e819d6ef5218UL,
        0xd69906245565a910UL,
        0xf40e35855771202aUL,
        0x106aa07032bbd1b8UL,
        0x19a4c116b8d2d0c8UL,
        0x1e376c085141ab53UL,
        0x2748774cdf8eeb99UL,
        0x34b0bcb5e19b48a8UL,
        0x391c0cb3c5c95a63UL,
        0x4ed8aa4ae3418acbUL,
        0x5b9cca4f7763e373UL,
        0x682e6ff3d6b2b8a3UL,
        0x748f82ee5defb2fcUL,
        0x78a5636f43172f60UL,
        0x84c87814a1f0ab72UL,
        0x8cc702081a6439ecUL,
        0x90befffa23631e28UL,
        0xa4506cebde82bde9UL,
        0xbef9a3f7b2c67915UL,
        0xc67178f2e372532bUL,
        0xca273eceea26619cUL,
        0xd186b8c721c0c207UL,
        0xeada7dd6cde0eb1eUL,
        0xf57d4f7fee6ed178UL,
        0x6f067aa72176fbaUL,
        0xa637dc5a2c898a6UL,
        0x113f9804bef90daeUL,
        0x1b710b35131c471bUL,
        0x28db77f523047d84UL,
        0x32caab7b40c72493UL,
        0x3c9ebe0a15c9bebcUL,
        0x431d67c49c100d4cUL,
        0x4cc5d4becb3e42b6UL,
        0x597f299cfc657e2aUL,
        0x5fcb6fab3ad6faecUL,
        0x6c44198c4a475817UL,
    };

    void Transform_Sha512_Len(wc_Sha512* sha512, const byte* data, word32 len)
    {
        __asm__ __volatile__ (
            /* Load digest into working vars */
            "vldm.64	%[sha512], {d0-d7}\n\t"
            /* Start of loop processing a block */
            "\n"
        "L_sha512_len_neon_begin_%=: \n\t"
            /* Load W */
            "vldm.64	%[data]!, {d16-d31}\n\t"
            "vrev64.8	q8, q8\n\t"
            "vrev64.8	q9, q9\n\t"
            "vrev64.8	q10, q10\n\t"
            "vrev64.8	q11, q11\n\t"
            "vrev64.8	q12, q12\n\t"
            "vrev64.8	q13, q13\n\t"
            "vrev64.8	q14, q14\n\t"
            "vrev64.8	q15, q15\n\t"
            "mov	r3, %[L_SHA512_transform_neon_len_k]\n\t"
            "mov	r12, #4\n\t"
            /* Start of 16 rounds */
            "\n"
        "L_sha512_len_neon_start_%=: \n\t"
            /* Round 0 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d4, #50\n\t"
            "vsri.u64	d8, d4, #14\n\t"
            "vshl.u64	d9, d0, #36\n\t"
            "vsri.u64	d9, d0, #28\n\t"
            "vshl.u64	d10, d4, #46\n\t"
            "vsri.u64	d10, d4, #18\n\t"
            "vshl.u64	d11, d0, #30\n\t"
            "vsri.u64	d11, d0, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d4, #23\n\t"
            "vsri.u64	d10, d4, #41\n\t"
            "vshl.u64	d11, d0, #25\n\t"
            "vsri.u64	d11, d0, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d7, d8\n\t"
            "vadd.i64	d12, d16\n\t"
            "vmov	d8, d4\n\t"
            "veor	d10, d1, d2\n\t"
            "vadd.i64	d7, d12\n\t"
            "vbsl	d8, d5, d6\n\t"
            "vbsl	d10, d0, d2\n\t"
            "vadd.i64	d7, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d3, d7\n\t"
            "vadd.i64	d7, d10\n\t"
            /* Round 1 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d3, #50\n\t"
            "vsri.u64	d8, d3, #14\n\t"
            "vshl.u64	d9, d7, #36\n\t"
            "vsri.u64	d9, d7, #28\n\t"
            "vshl.u64	d10, d3, #46\n\t"
            "vsri.u64	d10, d3, #18\n\t"
            "vshl.u64	d11, d7, #30\n\t"
            "vsri.u64	d11, d7, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d3, #23\n\t"
            "vsri.u64	d10, d3, #41\n\t"
            "vshl.u64	d11, d7, #25\n\t"
            "vsri.u64	d11, d7, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d6, d8\n\t"
            "vadd.i64	d12, d17\n\t"
            "vmov	d8, d3\n\t"
            "veor	d10, d0, d1\n\t"
            "vadd.i64	d6, d12\n\t"
            "vbsl	d8, d4, d5\n\t"
            "vbsl	d10, d7, d1\n\t"
            "vadd.i64	d6, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d2, d6\n\t"
            "vadd.i64	d6, d10\n\t"
            /* Calc new W[0]-W[1] */
            "vext.8	q6, q8, q9, #8\n\t"
            "vshl.u64	q4, q15, #45\n\t"
            "vsri.u64	q4, q15, #19\n\t"
            "vshl.u64	q5, q15, #3\n\t"
            "vsri.u64	q5, q15, #61\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q4, q15, #6\n\t"
            "veor	q5, q4\n\t"
            "vadd.i64	q8, q5\n\t"
            "vext.8	q7, q12, q13, #8\n\t"
            "vadd.i64	q8, q7\n\t"
            "vshl.u64	q4, q6, #63\n\t"
            "vsri.u64	q4, q6, #1\n\t"
            "vshl.u64	q5, q6, #56\n\t"
            "vsri.u64	q5, q6, #8\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q6, #7\n\t"
            "veor	q5, q6\n\t"
            "vadd.i64	q8, q5\n\t"
            /* Round 2 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d2, #50\n\t"
            "vsri.u64	d8, d2, #14\n\t"
            "vshl.u64	d9, d6, #36\n\t"
            "vsri.u64	d9, d6, #28\n\t"
            "vshl.u64	d10, d2, #46\n\t"
            "vsri.u64	d10, d2, #18\n\t"
            "vshl.u64	d11, d6, #30\n\t"
            "vsri.u64	d11, d6, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d2, #23\n\t"
            "vsri.u64	d10, d2, #41\n\t"
            "vshl.u64	d11, d6, #25\n\t"
            "vsri.u64	d11, d6, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d5, d8\n\t"
            "vadd.i64	d12, d18\n\t"
            "vmov	d8, d2\n\t"
            "veor	d10, d7, d0\n\t"
            "vadd.i64	d5, d12\n\t"
            "vbsl	d8, d3, d4\n\t"
            "vbsl	d10, d6, d0\n\t"
            "vadd.i64	d5, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d1, d5\n\t"
            "vadd.i64	d5, d10\n\t"
            /* Round 3 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d1, #50\n\t"
            "vsri.u64	d8, d1, #14\n\t"
            "vshl.u64	d9, d5, #36\n\t"
            "vsri.u64	d9, d5, #28\n\t"
            "vshl.u64	d10, d1, #46\n\t"
            "vsri.u64	d10, d1, #18\n\t"
            "vshl.u64	d11, d5, #30\n\t"
            "vsri.u64	d11, d5, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d1, #23\n\t"
            "vsri.u64	d10, d1, #41\n\t"
            "vshl.u64	d11, d5, #25\n\t"
            "vsri.u64	d11, d5, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d4, d8\n\t"
            "vadd.i64	d12, d19\n\t"
            "vmov	d8, d1\n\t"
            "veor	d10, d6, d7\n\t"
            "vadd.i64	d4, d12\n\t"
            "vbsl	d8, d2, d3\n\t"
            "vbsl	d10, d5, d7\n\t"
            "vadd.i64	d4, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d0, d4\n\t"
            "vadd.i64	d4, d10\n\t"
            /* Calc new W[2]-W[3] */
            "vext.8	q6, q9, q10, #8\n\t"
            "vshl.u64	q4, q8, #45\n\t"
            "vsri.u64	q4, q8, #19\n\t"
            "vshl.u64	q5, q8, #3\n\t"
            "vsri.u64	q5, q8, #61\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q4, q8, #6\n\t"
            "veor	q5, q4\n\t"
            "vadd.i64	q9, q5\n\t"
            "vext.8	q7, q13, q14, #8\n\t"
            "vadd.i64	q9, q7\n\t"
            "vshl.u64	q4, q6, #63\n\t"
            "vsri.u64	q4, q6, #1\n\t"
            "vshl.u64	q5, q6, #56\n\t"
            "vsri.u64	q5, q6, #8\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q6, #7\n\t"
            "veor	q5, q6\n\t"
            "vadd.i64	q9, q5\n\t"
            /* Round 4 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d0, #50\n\t"
            "vsri.u64	d8, d0, #14\n\t"
            "vshl.u64	d9, d4, #36\n\t"
            "vsri.u64	d9, d4, #28\n\t"
            "vshl.u64	d10, d0, #46\n\t"
            "vsri.u64	d10, d0, #18\n\t"
            "vshl.u64	d11, d4, #30\n\t"
            "vsri.u64	d11, d4, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d0, #23\n\t"
            "vsri.u64	d10, d0, #41\n\t"
            "vshl.u64	d11, d4, #25\n\t"
            "vsri.u64	d11, d4, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d3, d8\n\t"
            "vadd.i64	d12, d20\n\t"
            "vmov	d8, d0\n\t"
            "veor	d10, d5, d6\n\t"
            "vadd.i64	d3, d12\n\t"
            "vbsl	d8, d1, d2\n\t"
            "vbsl	d10, d4, d6\n\t"
            "vadd.i64	d3, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d7, d3\n\t"
            "vadd.i64	d3, d10\n\t"
            /* Round 5 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d7, #50\n\t"
            "vsri.u64	d8, d7, #14\n\t"
            "vshl.u64	d9, d3, #36\n\t"
            "vsri.u64	d9, d3, #28\n\t"
            "vshl.u64	d10, d7, #46\n\t"
            "vsri.u64	d10, d7, #18\n\t"
            "vshl.u64	d11, d3, #30\n\t"
            "vsri.u64	d11, d3, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d7, #23\n\t"
            "vsri.u64	d10, d7, #41\n\t"
            "vshl.u64	d11, d3, #25\n\t"
            "vsri.u64	d11, d3, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d2, d8\n\t"
            "vadd.i64	d12, d21\n\t"
            "vmov	d8, d7\n\t"
            "veor	d10, d4, d5\n\t"
            "vadd.i64	d2, d12\n\t"
            "vbsl	d8, d0, d1\n\t"
            "vbsl	d10, d3, d5\n\t"
            "vadd.i64	d2, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d6, d2\n\t"
            "vadd.i64	d2, d10\n\t"
            /* Calc new W[4]-W[5] */
            "vext.8	q6, q10, q11, #8\n\t"
            "vshl.u64	q4, q9, #45\n\t"
            "vsri.u64	q4, q9, #19\n\t"
            "vshl.u64	q5, q9, #3\n\t"
            "vsri.u64	q5, q9, #61\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q4, q9, #6\n\t"
            "veor	q5, q4\n\t"
            "vadd.i64	q10, q5\n\t"
            "vext.8	q7, q14, q15, #8\n\t"
            "vadd.i64	q10, q7\n\t"
            "vshl.u64	q4, q6, #63\n\t"
            "vsri.u64	q4, q6, #1\n\t"
            "vshl.u64	q5, q6, #56\n\t"
            "vsri.u64	q5, q6, #8\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q6, #7\n\t"
            "veor	q5, q6\n\t"
            "vadd.i64	q10, q5\n\t"
            /* Round 6 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d6, #50\n\t"
            "vsri.u64	d8, d6, #14\n\t"
            "vshl.u64	d9, d2, #36\n\t"
            "vsri.u64	d9, d2, #28\n\t"
            "vshl.u64	d10, d6, #46\n\t"
            "vsri.u64	d10, d6, #18\n\t"
            "vshl.u64	d11, d2, #30\n\t"
            "vsri.u64	d11, d2, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d6, #23\n\t"
            "vsri.u64	d10, d6, #41\n\t"
            "vshl.u64	d11, d2, #25\n\t"
            "vsri.u64	d11, d2, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d1, d8\n\t"
            "vadd.i64	d12, d22\n\t"
            "vmov	d8, d6\n\t"
            "veor	d10, d3, d4\n\t"
            "vadd.i64	d1, d12\n\t"
            "vbsl	d8, d7, d0\n\t"
            "vbsl	d10, d2, d4\n\t"
            "vadd.i64	d1, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d5, d1\n\t"
            "vadd.i64	d1, d10\n\t"
            /* Round 7 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d5, #50\n\t"
            "vsri.u64	d8, d5, #14\n\t"
            "vshl.u64	d9, d1, #36\n\t"
            "vsri.u64	d9, d1, #28\n\t"
            "vshl.u64	d10, d5, #46\n\t"
            "vsri.u64	d10, d5, #18\n\t"
            "vshl.u64	d11, d1, #30\n\t"
            "vsri.u64	d11, d1, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d5, #23\n\t"
            "vsri.u64	d10, d5, #41\n\t"
            "vshl.u64	d11, d1, #25\n\t"
            "vsri.u64	d11, d1, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d0, d8\n\t"
            "vadd.i64	d12, d23\n\t"
            "vmov	d8, d5\n\t"
            "veor	d10, d2, d3\n\t"
            "vadd.i64	d0, d12\n\t"
            "vbsl	d8, d6, d7\n\t"
            "vbsl	d10, d1, d3\n\t"
            "vadd.i64	d0, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d4, d0\n\t"
            "vadd.i64	d0, d10\n\t"
            /* Calc new W[6]-W[7] */
            "vext.8	q6, q11, q12, #8\n\t"
            "vshl.u64	q4, q10, #45\n\t"
            "vsri.u64	q4, q10, #19\n\t"
            "vshl.u64	q5, q10, #3\n\t"
            "vsri.u64	q5, q10, #61\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q4, q10, #6\n\t"
            "veor	q5, q4\n\t"
            "vadd.i64	q11, q5\n\t"
            "vext.8	q7, q15, q8, #8\n\t"
            "vadd.i64	q11, q7\n\t"
            "vshl.u64	q4, q6, #63\n\t"
            "vsri.u64	q4, q6, #1\n\t"
            "vshl.u64	q5, q6, #56\n\t"
            "vsri.u64	q5, q6, #8\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q6, #7\n\t"
            "veor	q5, q6\n\t"
            "vadd.i64	q11, q5\n\t"
            /* Round 8 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d4, #50\n\t"
            "vsri.u64	d8, d4, #14\n\t"
            "vshl.u64	d9, d0, #36\n\t"
            "vsri.u64	d9, d0, #28\n\t"
            "vshl.u64	d10, d4, #46\n\t"
            "vsri.u64	d10, d4, #18\n\t"
            "vshl.u64	d11, d0, #30\n\t"
            "vsri.u64	d11, d0, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d4, #23\n\t"
            "vsri.u64	d10, d4, #41\n\t"
            "vshl.u64	d11, d0, #25\n\t"
            "vsri.u64	d11, d0, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d7, d8\n\t"
            "vadd.i64	d12, d24\n\t"
            "vmov	d8, d4\n\t"
            "veor	d10, d1, d2\n\t"
            "vadd.i64	d7, d12\n\t"
            "vbsl	d8, d5, d6\n\t"
            "vbsl	d10, d0, d2\n\t"
            "vadd.i64	d7, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d3, d7\n\t"
            "vadd.i64	d7, d10\n\t"
            /* Round 9 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d3, #50\n\t"
            "vsri.u64	d8, d3, #14\n\t"
            "vshl.u64	d9, d7, #36\n\t"
            "vsri.u64	d9, d7, #28\n\t"
            "vshl.u64	d10, d3, #46\n\t"
            "vsri.u64	d10, d3, #18\n\t"
            "vshl.u64	d11, d7, #30\n\t"
            "vsri.u64	d11, d7, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d3, #23\n\t"
            "vsri.u64	d10, d3, #41\n\t"
            "vshl.u64	d11, d7, #25\n\t"
            "vsri.u64	d11, d7, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d6, d8\n\t"
            "vadd.i64	d12, d25\n\t"
            "vmov	d8, d3\n\t"
            "veor	d10, d0, d1\n\t"
            "vadd.i64	d6, d12\n\t"
            "vbsl	d8, d4, d5\n\t"
            "vbsl	d10, d7, d1\n\t"
            "vadd.i64	d6, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d2, d6\n\t"
            "vadd.i64	d6, d10\n\t"
            /* Calc new W[8]-W[9] */
            "vext.8	q6, q12, q13, #8\n\t"
            "vshl.u64	q4, q11, #45\n\t"
            "vsri.u64	q4, q11, #19\n\t"
            "vshl.u64	q5, q11, #3\n\t"
            "vsri.u64	q5, q11, #61\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q4, q11, #6\n\t"
            "veor	q5, q4\n\t"
            "vadd.i64	q12, q5\n\t"
            "vext.8	q7, q8, q9, #8\n\t"
            "vadd.i64	q12, q7\n\t"
            "vshl.u64	q4, q6, #63\n\t"
            "vsri.u64	q4, q6, #1\n\t"
            "vshl.u64	q5, q6, #56\n\t"
            "vsri.u64	q5, q6, #8\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q6, #7\n\t"
            "veor	q5, q6\n\t"
            "vadd.i64	q12, q5\n\t"
            /* Round 10 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d2, #50\n\t"
            "vsri.u64	d8, d2, #14\n\t"
            "vshl.u64	d9, d6, #36\n\t"
            "vsri.u64	d9, d6, #28\n\t"
            "vshl.u64	d10, d2, #46\n\t"
            "vsri.u64	d10, d2, #18\n\t"
            "vshl.u64	d11, d6, #30\n\t"
            "vsri.u64	d11, d6, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d2, #23\n\t"
            "vsri.u64	d10, d2, #41\n\t"
            "vshl.u64	d11, d6, #25\n\t"
            "vsri.u64	d11, d6, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d5, d8\n\t"
            "vadd.i64	d12, d26\n\t"
            "vmov	d8, d2\n\t"
            "veor	d10, d7, d0\n\t"
            "vadd.i64	d5, d12\n\t"
            "vbsl	d8, d3, d4\n\t"
            "vbsl	d10, d6, d0\n\t"
            "vadd.i64	d5, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d1, d5\n\t"
            "vadd.i64	d5, d10\n\t"
            /* Round 11 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d1, #50\n\t"
            "vsri.u64	d8, d1, #14\n\t"
            "vshl.u64	d9, d5, #36\n\t"
            "vsri.u64	d9, d5, #28\n\t"
            "vshl.u64	d10, d1, #46\n\t"
            "vsri.u64	d10, d1, #18\n\t"
            "vshl.u64	d11, d5, #30\n\t"
            "vsri.u64	d11, d5, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d1, #23\n\t"
            "vsri.u64	d10, d1, #41\n\t"
            "vshl.u64	d11, d5, #25\n\t"
            "vsri.u64	d11, d5, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d4, d8\n\t"
            "vadd.i64	d12, d27\n\t"
            "vmov	d8, d1\n\t"
            "veor	d10, d6, d7\n\t"
            "vadd.i64	d4, d12\n\t"
            "vbsl	d8, d2, d3\n\t"
            "vbsl	d10, d5, d7\n\t"
            "vadd.i64	d4, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d0, d4\n\t"
            "vadd.i64	d4, d10\n\t"
            /* Calc new W[10]-W[11] */
            "vext.8	q6, q13, q14, #8\n\t"
            "vshl.u64	q4, q12, #45\n\t"
            "vsri.u64	q4, q12, #19\n\t"
            "vshl.u64	q5, q12, #3\n\t"
            "vsri.u64	q5, q12, #61\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q4, q12, #6\n\t"
            "veor	q5, q4\n\t"
            "vadd.i64	q13, q5\n\t"
            "vext.8	q7, q9, q10, #8\n\t"
            "vadd.i64	q13, q7\n\t"
            "vshl.u64	q4, q6, #63\n\t"
            "vsri.u64	q4, q6, #1\n\t"
            "vshl.u64	q5, q6, #56\n\t"
            "vsri.u64	q5, q6, #8\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q6, #7\n\t"
            "veor	q5, q6\n\t"
            "vadd.i64	q13, q5\n\t"
            /* Round 12 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d0, #50\n\t"
            "vsri.u64	d8, d0, #14\n\t"
            "vshl.u64	d9, d4, #36\n\t"
            "vsri.u64	d9, d4, #28\n\t"
            "vshl.u64	d10, d0, #46\n\t"
            "vsri.u64	d10, d0, #18\n\t"
            "vshl.u64	d11, d4, #30\n\t"
            "vsri.u64	d11, d4, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d0, #23\n\t"
            "vsri.u64	d10, d0, #41\n\t"
            "vshl.u64	d11, d4, #25\n\t"
            "vsri.u64	d11, d4, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d3, d8\n\t"
            "vadd.i64	d12, d28\n\t"
            "vmov	d8, d0\n\t"
            "veor	d10, d5, d6\n\t"
            "vadd.i64	d3, d12\n\t"
            "vbsl	d8, d1, d2\n\t"
            "vbsl	d10, d4, d6\n\t"
            "vadd.i64	d3, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d7, d3\n\t"
            "vadd.i64	d3, d10\n\t"
            /* Round 13 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d7, #50\n\t"
            "vsri.u64	d8, d7, #14\n\t"
            "vshl.u64	d9, d3, #36\n\t"
            "vsri.u64	d9, d3, #28\n\t"
            "vshl.u64	d10, d7, #46\n\t"
            "vsri.u64	d10, d7, #18\n\t"
            "vshl.u64	d11, d3, #30\n\t"
            "vsri.u64	d11, d3, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d7, #23\n\t"
            "vsri.u64	d10, d7, #41\n\t"
            "vshl.u64	d11, d3, #25\n\t"
            "vsri.u64	d11, d3, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d2, d8\n\t"
            "vadd.i64	d12, d29\n\t"
            "vmov	d8, d7\n\t"
            "veor	d10, d4, d5\n\t"
            "vadd.i64	d2, d12\n\t"
            "vbsl	d8, d0, d1\n\t"
            "vbsl	d10, d3, d5\n\t"
            "vadd.i64	d2, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d6, d2\n\t"
            "vadd.i64	d2, d10\n\t"
            /* Calc new W[12]-W[13] */
            "vext.8	q6, q14, q15, #8\n\t"
            "vshl.u64	q4, q13, #45\n\t"
            "vsri.u64	q4, q13, #19\n\t"
            "vshl.u64	q5, q13, #3\n\t"
            "vsri.u64	q5, q13, #61\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q4, q13, #6\n\t"
            "veor	q5, q4\n\t"
            "vadd.i64	q14, q5\n\t"
            "vext.8	q7, q10, q11, #8\n\t"
            "vadd.i64	q14, q7\n\t"
            "vshl.u64	q4, q6, #63\n\t"
            "vsri.u64	q4, q6, #1\n\t"
            "vshl.u64	q5, q6, #56\n\t"
            "vsri.u64	q5, q6, #8\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q6, #7\n\t"
            "veor	q5, q6\n\t"
            "vadd.i64	q14, q5\n\t"
            /* Round 14 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d6, #50\n\t"
            "vsri.u64	d8, d6, #14\n\t"
            "vshl.u64	d9, d2, #36\n\t"
            "vsri.u64	d9, d2, #28\n\t"
            "vshl.u64	d10, d6, #46\n\t"
            "vsri.u64	d10, d6, #18\n\t"
            "vshl.u64	d11, d2, #30\n\t"
            "vsri.u64	d11, d2, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d6, #23\n\t"
            "vsri.u64	d10, d6, #41\n\t"
            "vshl.u64	d11, d2, #25\n\t"
            "vsri.u64	d11, d2, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d1, d8\n\t"
            "vadd.i64	d12, d30\n\t"
            "vmov	d8, d6\n\t"
            "veor	d10, d3, d4\n\t"
            "vadd.i64	d1, d12\n\t"
            "vbsl	d8, d7, d0\n\t"
            "vbsl	d10, d2, d4\n\t"
            "vadd.i64	d1, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d5, d1\n\t"
            "vadd.i64	d1, d10\n\t"
            /* Round 15 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d5, #50\n\t"
            "vsri.u64	d8, d5, #14\n\t"
            "vshl.u64	d9, d1, #36\n\t"
            "vsri.u64	d9, d1, #28\n\t"
            "vshl.u64	d10, d5, #46\n\t"
            "vsri.u64	d10, d5, #18\n\t"
            "vshl.u64	d11, d1, #30\n\t"
            "vsri.u64	d11, d1, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d5, #23\n\t"
            "vsri.u64	d10, d5, #41\n\t"
            "vshl.u64	d11, d1, #25\n\t"
            "vsri.u64	d11, d1, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d0, d8\n\t"
            "vadd.i64	d12, d31\n\t"
            "vmov	d8, d5\n\t"
            "veor	d10, d2, d3\n\t"
            "vadd.i64	d0, d12\n\t"
            "vbsl	d8, d6, d7\n\t"
            "vbsl	d10, d1, d3\n\t"
            "vadd.i64	d0, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d4, d0\n\t"
            "vadd.i64	d0, d10\n\t"
            /* Calc new W[14]-W[15] */
            "vext.8	q6, q15, q8, #8\n\t"
            "vshl.u64	q4, q14, #45\n\t"
            "vsri.u64	q4, q14, #19\n\t"
            "vshl.u64	q5, q14, #3\n\t"
            "vsri.u64	q5, q14, #61\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q4, q14, #6\n\t"
            "veor	q5, q4\n\t"
            "vadd.i64	q15, q5\n\t"
            "vext.8	q7, q11, q12, #8\n\t"
            "vadd.i64	q15, q7\n\t"
            "vshl.u64	q4, q6, #63\n\t"
            "vsri.u64	q4, q6, #1\n\t"
            "vshl.u64	q5, q6, #56\n\t"
            "vsri.u64	q5, q6, #8\n\t"
            "veor	q5, q4\n\t"
            "vshr.u64	q6, #7\n\t"
            "veor	q5, q6\n\t"
            "vadd.i64	q15, q5\n\t"
            "subs	r12, r12, #1\n\t"
            "bne	L_sha512_len_neon_start_%=\n\t"
            /* Round 0 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d4, #50\n\t"
            "vsri.u64	d8, d4, #14\n\t"
            "vshl.u64	d9, d0, #36\n\t"
            "vsri.u64	d9, d0, #28\n\t"
            "vshl.u64	d10, d4, #46\n\t"
            "vsri.u64	d10, d4, #18\n\t"
            "vshl.u64	d11, d0, #30\n\t"
            "vsri.u64	d11, d0, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d4, #23\n\t"
            "vsri.u64	d10, d4, #41\n\t"
            "vshl.u64	d11, d0, #25\n\t"
            "vsri.u64	d11, d0, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d7, d8\n\t"
            "vadd.i64	d12, d16\n\t"
            "vmov	d8, d4\n\t"
            "veor	d10, d1, d2\n\t"
            "vadd.i64	d7, d12\n\t"
            "vbsl	d8, d5, d6\n\t"
            "vbsl	d10, d0, d2\n\t"
            "vadd.i64	d7, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d3, d7\n\t"
            "vadd.i64	d7, d10\n\t"
            /* Round 1 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d3, #50\n\t"
            "vsri.u64	d8, d3, #14\n\t"
            "vshl.u64	d9, d7, #36\n\t"
            "vsri.u64	d9, d7, #28\n\t"
            "vshl.u64	d10, d3, #46\n\t"
            "vsri.u64	d10, d3, #18\n\t"
            "vshl.u64	d11, d7, #30\n\t"
            "vsri.u64	d11, d7, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d3, #23\n\t"
            "vsri.u64	d10, d3, #41\n\t"
            "vshl.u64	d11, d7, #25\n\t"
            "vsri.u64	d11, d7, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d6, d8\n\t"
            "vadd.i64	d12, d17\n\t"
            "vmov	d8, d3\n\t"
            "veor	d10, d0, d1\n\t"
            "vadd.i64	d6, d12\n\t"
            "vbsl	d8, d4, d5\n\t"
            "vbsl	d10, d7, d1\n\t"
            "vadd.i64	d6, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d2, d6\n\t"
            "vadd.i64	d6, d10\n\t"
            /* Round 2 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d2, #50\n\t"
            "vsri.u64	d8, d2, #14\n\t"
            "vshl.u64	d9, d6, #36\n\t"
            "vsri.u64	d9, d6, #28\n\t"
            "vshl.u64	d10, d2, #46\n\t"
            "vsri.u64	d10, d2, #18\n\t"
            "vshl.u64	d11, d6, #30\n\t"
            "vsri.u64	d11, d6, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d2, #23\n\t"
            "vsri.u64	d10, d2, #41\n\t"
            "vshl.u64	d11, d6, #25\n\t"
            "vsri.u64	d11, d6, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d5, d8\n\t"
            "vadd.i64	d12, d18\n\t"
            "vmov	d8, d2\n\t"
            "veor	d10, d7, d0\n\t"
            "vadd.i64	d5, d12\n\t"
            "vbsl	d8, d3, d4\n\t"
            "vbsl	d10, d6, d0\n\t"
            "vadd.i64	d5, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d1, d5\n\t"
            "vadd.i64	d5, d10\n\t"
            /* Round 3 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d1, #50\n\t"
            "vsri.u64	d8, d1, #14\n\t"
            "vshl.u64	d9, d5, #36\n\t"
            "vsri.u64	d9, d5, #28\n\t"
            "vshl.u64	d10, d1, #46\n\t"
            "vsri.u64	d10, d1, #18\n\t"
            "vshl.u64	d11, d5, #30\n\t"
            "vsri.u64	d11, d5, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d1, #23\n\t"
            "vsri.u64	d10, d1, #41\n\t"
            "vshl.u64	d11, d5, #25\n\t"
            "vsri.u64	d11, d5, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d4, d8\n\t"
            "vadd.i64	d12, d19\n\t"
            "vmov	d8, d1\n\t"
            "veor	d10, d6, d7\n\t"
            "vadd.i64	d4, d12\n\t"
            "vbsl	d8, d2, d3\n\t"
            "vbsl	d10, d5, d7\n\t"
            "vadd.i64	d4, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d0, d4\n\t"
            "vadd.i64	d4, d10\n\t"
            /* Round 4 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d0, #50\n\t"
            "vsri.u64	d8, d0, #14\n\t"
            "vshl.u64	d9, d4, #36\n\t"
            "vsri.u64	d9, d4, #28\n\t"
            "vshl.u64	d10, d0, #46\n\t"
            "vsri.u64	d10, d0, #18\n\t"
            "vshl.u64	d11, d4, #30\n\t"
            "vsri.u64	d11, d4, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d0, #23\n\t"
            "vsri.u64	d10, d0, #41\n\t"
            "vshl.u64	d11, d4, #25\n\t"
            "vsri.u64	d11, d4, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d3, d8\n\t"
            "vadd.i64	d12, d20\n\t"
            "vmov	d8, d0\n\t"
            "veor	d10, d5, d6\n\t"
            "vadd.i64	d3, d12\n\t"
            "vbsl	d8, d1, d2\n\t"
            "vbsl	d10, d4, d6\n\t"
            "vadd.i64	d3, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d7, d3\n\t"
            "vadd.i64	d3, d10\n\t"
            /* Round 5 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d7, #50\n\t"
            "vsri.u64	d8, d7, #14\n\t"
            "vshl.u64	d9, d3, #36\n\t"
            "vsri.u64	d9, d3, #28\n\t"
            "vshl.u64	d10, d7, #46\n\t"
            "vsri.u64	d10, d7, #18\n\t"
            "vshl.u64	d11, d3, #30\n\t"
            "vsri.u64	d11, d3, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d7, #23\n\t"
            "vsri.u64	d10, d7, #41\n\t"
            "vshl.u64	d11, d3, #25\n\t"
            "vsri.u64	d11, d3, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d2, d8\n\t"
            "vadd.i64	d12, d21\n\t"
            "vmov	d8, d7\n\t"
            "veor	d10, d4, d5\n\t"
            "vadd.i64	d2, d12\n\t"
            "vbsl	d8, d0, d1\n\t"
            "vbsl	d10, d3, d5\n\t"
            "vadd.i64	d2, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d6, d2\n\t"
            "vadd.i64	d2, d10\n\t"
            /* Round 6 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d6, #50\n\t"
            "vsri.u64	d8, d6, #14\n\t"
            "vshl.u64	d9, d2, #36\n\t"
            "vsri.u64	d9, d2, #28\n\t"
            "vshl.u64	d10, d6, #46\n\t"
            "vsri.u64	d10, d6, #18\n\t"
            "vshl.u64	d11, d2, #30\n\t"
            "vsri.u64	d11, d2, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d6, #23\n\t"
            "vsri.u64	d10, d6, #41\n\t"
            "vshl.u64	d11, d2, #25\n\t"
            "vsri.u64	d11, d2, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d1, d8\n\t"
            "vadd.i64	d12, d22\n\t"
            "vmov	d8, d6\n\t"
            "veor	d10, d3, d4\n\t"
            "vadd.i64	d1, d12\n\t"
            "vbsl	d8, d7, d0\n\t"
            "vbsl	d10, d2, d4\n\t"
            "vadd.i64	d1, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d5, d1\n\t"
            "vadd.i64	d1, d10\n\t"
            /* Round 7 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d5, #50\n\t"
            "vsri.u64	d8, d5, #14\n\t"
            "vshl.u64	d9, d1, #36\n\t"
            "vsri.u64	d9, d1, #28\n\t"
            "vshl.u64	d10, d5, #46\n\t"
            "vsri.u64	d10, d5, #18\n\t"
            "vshl.u64	d11, d1, #30\n\t"
            "vsri.u64	d11, d1, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d5, #23\n\t"
            "vsri.u64	d10, d5, #41\n\t"
            "vshl.u64	d11, d1, #25\n\t"
            "vsri.u64	d11, d1, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d0, d8\n\t"
            "vadd.i64	d12, d23\n\t"
            "vmov	d8, d5\n\t"
            "veor	d10, d2, d3\n\t"
            "vadd.i64	d0, d12\n\t"
            "vbsl	d8, d6, d7\n\t"
            "vbsl	d10, d1, d3\n\t"
            "vadd.i64	d0, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d4, d0\n\t"
            "vadd.i64	d0, d10\n\t"
            /* Round 8 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d4, #50\n\t"
            "vsri.u64	d8, d4, #14\n\t"
            "vshl.u64	d9, d0, #36\n\t"
            "vsri.u64	d9, d0, #28\n\t"
            "vshl.u64	d10, d4, #46\n\t"
            "vsri.u64	d10, d4, #18\n\t"
            "vshl.u64	d11, d0, #30\n\t"
            "vsri.u64	d11, d0, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d4, #23\n\t"
            "vsri.u64	d10, d4, #41\n\t"
            "vshl.u64	d11, d0, #25\n\t"
            "vsri.u64	d11, d0, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d7, d8\n\t"
            "vadd.i64	d12, d24\n\t"
            "vmov	d8, d4\n\t"
            "veor	d10, d1, d2\n\t"
            "vadd.i64	d7, d12\n\t"
            "vbsl	d8, d5, d6\n\t"
            "vbsl	d10, d0, d2\n\t"
            "vadd.i64	d7, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d3, d7\n\t"
            "vadd.i64	d7, d10\n\t"
            /* Round 9 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d3, #50\n\t"
            "vsri.u64	d8, d3, #14\n\t"
            "vshl.u64	d9, d7, #36\n\t"
            "vsri.u64	d9, d7, #28\n\t"
            "vshl.u64	d10, d3, #46\n\t"
            "vsri.u64	d10, d3, #18\n\t"
            "vshl.u64	d11, d7, #30\n\t"
            "vsri.u64	d11, d7, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d3, #23\n\t"
            "vsri.u64	d10, d3, #41\n\t"
            "vshl.u64	d11, d7, #25\n\t"
            "vsri.u64	d11, d7, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d6, d8\n\t"
            "vadd.i64	d12, d25\n\t"
            "vmov	d8, d3\n\t"
            "veor	d10, d0, d1\n\t"
            "vadd.i64	d6, d12\n\t"
            "vbsl	d8, d4, d5\n\t"
            "vbsl	d10, d7, d1\n\t"
            "vadd.i64	d6, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d2, d6\n\t"
            "vadd.i64	d6, d10\n\t"
            /* Round 10 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d2, #50\n\t"
            "vsri.u64	d8, d2, #14\n\t"
            "vshl.u64	d9, d6, #36\n\t"
            "vsri.u64	d9, d6, #28\n\t"
            "vshl.u64	d10, d2, #46\n\t"
            "vsri.u64	d10, d2, #18\n\t"
            "vshl.u64	d11, d6, #30\n\t"
            "vsri.u64	d11, d6, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d2, #23\n\t"
            "vsri.u64	d10, d2, #41\n\t"
            "vshl.u64	d11, d6, #25\n\t"
            "vsri.u64	d11, d6, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d5, d8\n\t"
            "vadd.i64	d12, d26\n\t"
            "vmov	d8, d2\n\t"
            "veor	d10, d7, d0\n\t"
            "vadd.i64	d5, d12\n\t"
            "vbsl	d8, d3, d4\n\t"
            "vbsl	d10, d6, d0\n\t"
            "vadd.i64	d5, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d1, d5\n\t"
            "vadd.i64	d5, d10\n\t"
            /* Round 11 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d1, #50\n\t"
            "vsri.u64	d8, d1, #14\n\t"
            "vshl.u64	d9, d5, #36\n\t"
            "vsri.u64	d9, d5, #28\n\t"
            "vshl.u64	d10, d1, #46\n\t"
            "vsri.u64	d10, d1, #18\n\t"
            "vshl.u64	d11, d5, #30\n\t"
            "vsri.u64	d11, d5, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d1, #23\n\t"
            "vsri.u64	d10, d1, #41\n\t"
            "vshl.u64	d11, d5, #25\n\t"
            "vsri.u64	d11, d5, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d4, d8\n\t"
            "vadd.i64	d12, d27\n\t"
            "vmov	d8, d1\n\t"
            "veor	d10, d6, d7\n\t"
            "vadd.i64	d4, d12\n\t"
            "vbsl	d8, d2, d3\n\t"
            "vbsl	d10, d5, d7\n\t"
            "vadd.i64	d4, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d0, d4\n\t"
            "vadd.i64	d4, d10\n\t"
            /* Round 12 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d0, #50\n\t"
            "vsri.u64	d8, d0, #14\n\t"
            "vshl.u64	d9, d4, #36\n\t"
            "vsri.u64	d9, d4, #28\n\t"
            "vshl.u64	d10, d0, #46\n\t"
            "vsri.u64	d10, d0, #18\n\t"
            "vshl.u64	d11, d4, #30\n\t"
            "vsri.u64	d11, d4, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d0, #23\n\t"
            "vsri.u64	d10, d0, #41\n\t"
            "vshl.u64	d11, d4, #25\n\t"
            "vsri.u64	d11, d4, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d3, d8\n\t"
            "vadd.i64	d12, d28\n\t"
            "vmov	d8, d0\n\t"
            "veor	d10, d5, d6\n\t"
            "vadd.i64	d3, d12\n\t"
            "vbsl	d8, d1, d2\n\t"
            "vbsl	d10, d4, d6\n\t"
            "vadd.i64	d3, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d7, d3\n\t"
            "vadd.i64	d3, d10\n\t"
            /* Round 13 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d7, #50\n\t"
            "vsri.u64	d8, d7, #14\n\t"
            "vshl.u64	d9, d3, #36\n\t"
            "vsri.u64	d9, d3, #28\n\t"
            "vshl.u64	d10, d7, #46\n\t"
            "vsri.u64	d10, d7, #18\n\t"
            "vshl.u64	d11, d3, #30\n\t"
            "vsri.u64	d11, d3, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d7, #23\n\t"
            "vsri.u64	d10, d7, #41\n\t"
            "vshl.u64	d11, d3, #25\n\t"
            "vsri.u64	d11, d3, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d2, d8\n\t"
            "vadd.i64	d12, d29\n\t"
            "vmov	d8, d7\n\t"
            "veor	d10, d4, d5\n\t"
            "vadd.i64	d2, d12\n\t"
            "vbsl	d8, d0, d1\n\t"
            "vbsl	d10, d3, d5\n\t"
            "vadd.i64	d2, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d6, d2\n\t"
            "vadd.i64	d2, d10\n\t"
            /* Round 14 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d6, #50\n\t"
            "vsri.u64	d8, d6, #14\n\t"
            "vshl.u64	d9, d2, #36\n\t"
            "vsri.u64	d9, d2, #28\n\t"
            "vshl.u64	d10, d6, #46\n\t"
            "vsri.u64	d10, d6, #18\n\t"
            "vshl.u64	d11, d2, #30\n\t"
            "vsri.u64	d11, d2, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d6, #23\n\t"
            "vsri.u64	d10, d6, #41\n\t"
            "vshl.u64	d11, d2, #25\n\t"
            "vsri.u64	d11, d2, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d1, d8\n\t"
            "vadd.i64	d12, d30\n\t"
            "vmov	d8, d6\n\t"
            "veor	d10, d3, d4\n\t"
            "vadd.i64	d1, d12\n\t"
            "vbsl	d8, d7, d0\n\t"
            "vbsl	d10, d2, d4\n\t"
            "vadd.i64	d1, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d5, d1\n\t"
            "vadd.i64	d1, d10\n\t"
            /* Round 15 */
            "vld1.64	{d12}, [r3]!\n\t"
            "vshl.u64	d8, d5, #50\n\t"
            "vsri.u64	d8, d5, #14\n\t"
            "vshl.u64	d9, d1, #36\n\t"
            "vsri.u64	d9, d1, #28\n\t"
            "vshl.u64	d10, d5, #46\n\t"
            "vsri.u64	d10, d5, #18\n\t"
            "vshl.u64	d11, d1, #30\n\t"
            "vsri.u64	d11, d1, #34\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vshl.u64	d10, d5, #23\n\t"
            "vsri.u64	d10, d5, #41\n\t"
            "vshl.u64	d11, d1, #25\n\t"
            "vsri.u64	d11, d1, #39\n\t"
            "veor	d8, d10\n\t"
            "veor	d9, d11\n\t"
            "vadd.i64	d0, d8\n\t"
            "vadd.i64	d12, d31\n\t"
            "vmov	d8, d5\n\t"
            "veor	d10, d2, d3\n\t"
            "vadd.i64	d0, d12\n\t"
            "vbsl	d8, d6, d7\n\t"
            "vbsl	d10, d1, d3\n\t"
            "vadd.i64	d0, d8\n\t"
            "vadd.i64	d10, d9\n\t"
            "vadd.i64	d4, d0\n\t"
            "vadd.i64	d0, d10\n\t"
            /* Add in digest from start */
            "vldm.64	%[sha512], {d8-d15}\n\t"
            "vadd.i64	q0, q0, q4\n\t"
            "vadd.i64	q1, q1, q5\n\t"
            "vadd.i64	q2, q2, q6\n\t"
            "vadd.i64	q3, q3, q7\n\t"
            "vstm.64	%[sha512], {d0-d7}\n\t"
            "subs	%[len], %[len], #0x80\n\t"
            "bne	L_sha512_len_neon_begin_%=\n\t"
            : [sha512] "+r" (sha512), [data] "+r" (data), [len] "+r" (len)
            : [L_SHA512_transform_neon_len_k] "r" (L_SHA512_transform_neon_len_k)
            : "memory", "r3", "r12", "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15", "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15"
        );
    }

    #endif /* !WOLFSSL_ARMASM_NO_NEON */
    #endif /* WOLFSSL_ARMASM */
    #endif /* !__aarch64__ */
    /* end of: armv8-32-sha512-asm */

    /* start of: armv8-sha512 */

    #ifdef HAVE_CONFIG_H
        #include <config.h>
    #endif

    #include <wolfssl/wolfcrypt/settings.h>

    #ifdef WOLFSSL_ARMASM
    #if defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)

    #include <wolfssl/wolfcrypt/sha512.h>
    #include <wolfssl/wolfcrypt/error-crypt.h>
    #include <wolfssl/wolfcrypt/cpuid.h>
    #include <wolfssl/wolfcrypt/hash.h>

    #include <wolfssl/wolfcrypt/logging.h>

    #ifdef NO_INLINE
        #include <wolfssl/wolfcrypt/misc.h>
    #else
        #define WOLFSSL_MISC_INCLUDED
        #include <wolfcrypt/src/misc.c>
    #endif

    #ifdef WOLFSSL_SHA384
        int wc_Sha384FinalRaw(wc_Sha384* sha384, byte* hash);
    #endif

    #ifdef WOLFSSL_SHA512
        int wc_Sha512FinalRaw(wc_Sha512* sha512, byte* hash);
    #endif

    #ifdef WOLFSSL_SHA512

    static int InitSha512(wc_Sha512* sha512)
    {
        if (sha512 == NULL)
            return BAD_FUNC_ARG;

        sha512->digest[0] = W64LIT(0x6a09e667f3bcc908);
        sha512->digest[1] = W64LIT(0xbb67ae8584caa73b);
        sha512->digest[2] = W64LIT(0x3c6ef372fe94f82b);
        sha512->digest[3] = W64LIT(0xa54ff53a5f1d36f1);
        sha512->digest[4] = W64LIT(0x510e527fade682d1);
        sha512->digest[5] = W64LIT(0x9b05688c2b3e6c1f);
        sha512->digest[6] = W64LIT(0x1f83d9abfb41bd6b);
        sha512->digest[7] = W64LIT(0x5be0cd19137e2179);

        sha512->buffLen = 0;
        sha512->loLen   = 0;
        sha512->hiLen   = 0;
    #if defined(WOLFSSL_HASH_FLAGS) || defined(WOLF_CRYPTO_CB)
        sha512->flags = 0;
    #endif

        return 0;
    }

    #endif /* WOLFSSL_SHA512 */

    #ifdef WOLFSSL_SHA512

    int wc_InitSha512_ex(wc_Sha512* sha512, void* heap, int devId)
    {
        int ret = 0;

        if (sha512 == NULL)
            return BAD_FUNC_ARG;

        sha512->heap = heap;

        ret = InitSha512(sha512);
        if (ret != 0)
            return ret;

    #ifdef WOLFSSL_SMALL_STACK_CACHE
        sha512->W = NULL;
    #endif

        (void)devId;

        return ret;
    }

    #endif /* WOLFSSL_SHA512 */

    #ifndef WOLFSSL_ARMASM
    static const word64 K512[80] = {
        W64LIT(0x428a2f98d728ae22), W64LIT(0x7137449123ef65cd),
        W64LIT(0xb5c0fbcfec4d3b2f), W64LIT(0xe9b5dba58189dbbc),
        W64LIT(0x3956c25bf348b538), W64LIT(0x59f111f1b605d019),
        W64LIT(0x923f82a4af194f9b), W64LIT(0xab1c5ed5da6d8118),
        W64LIT(0xd807aa98a3030242), W64LIT(0x12835b0145706fbe),
        W64LIT(0x243185be4ee4b28c), W64LIT(0x550c7dc3d5ffb4e2),
        W64LIT(0x72be5d74f27b896f), W64LIT(0x80deb1fe3b1696b1),
        W64LIT(0x9bdc06a725c71235), W64LIT(0xc19bf174cf692694),
        W64LIT(0xe49b69c19ef14ad2), W64LIT(0xefbe4786384f25e3),
        W64LIT(0x0fc19dc68b8cd5b5), W64LIT(0x240ca1cc77ac9c65),
        W64LIT(0x2de92c6f592b0275), W64LIT(0x4a7484aa6ea6e483),
        W64LIT(0x5cb0a9dcbd41fbd4), W64LIT(0x76f988da831153b5),
        W64LIT(0x983e5152ee66dfab), W64LIT(0xa831c66d2db43210),
        W64LIT(0xb00327c898fb213f), W64LIT(0xbf597fc7beef0ee4),
        W64LIT(0xc6e00bf33da88fc2), W64LIT(0xd5a79147930aa725),
        W64LIT(0x06ca6351e003826f), W64LIT(0x142929670a0e6e70),
        W64LIT(0x27b70a8546d22ffc), W64LIT(0x2e1b21385c26c926),
        W64LIT(0x4d2c6dfc5ac42aed), W64LIT(0x53380d139d95b3df),
        W64LIT(0x650a73548baf63de), W64LIT(0x766a0abb3c77b2a8),
        W64LIT(0x81c2c92e47edaee6), W64LIT(0x92722c851482353b),
        W64LIT(0xa2bfe8a14cf10364), W64LIT(0xa81a664bbc423001),
        W64LIT(0xc24b8b70d0f89791), W64LIT(0xc76c51a30654be30),
        W64LIT(0xd192e819d6ef5218), W64LIT(0xd69906245565a910),
        W64LIT(0xf40e35855771202a), W64LIT(0x106aa07032bbd1b8),
        W64LIT(0x19a4c116b8d2d0c8), W64LIT(0x1e376c085141ab53),
        W64LIT(0x2748774cdf8eeb99), W64LIT(0x34b0bcb5e19b48a8),
        W64LIT(0x391c0cb3c5c95a63), W64LIT(0x4ed8aa4ae3418acb),
        W64LIT(0x5b9cca4f7763e373), W64LIT(0x682e6ff3d6b2b8a3),
        W64LIT(0x748f82ee5defb2fc), W64LIT(0x78a5636f43172f60),
        W64LIT(0x84c87814a1f0ab72), W64LIT(0x8cc702081a6439ec),
        W64LIT(0x90befffa23631e28), W64LIT(0xa4506cebde82bde9),
        W64LIT(0xbef9a3f7b2c67915), W64LIT(0xc67178f2e372532b),
        W64LIT(0xca273eceea26619c), W64LIT(0xd186b8c721c0c207),
        W64LIT(0xeada7dd6cde0eb1e), W64LIT(0xf57d4f7fee6ed178),
        W64LIT(0x06f067aa72176fba), W64LIT(0x0a637dc5a2c898a6),
        W64LIT(0x113f9804bef90dae), W64LIT(0x1b710b35131c471b),
        W64LIT(0x28db77f523047d84), W64LIT(0x32caab7b40c72493),
        W64LIT(0x3c9ebe0a15c9bebc), W64LIT(0x431d67c49c100d4c),
        W64LIT(0x4cc5d4becb3e42b6), W64LIT(0x597f299cfc657e2a),
        W64LIT(0x5fcb6fab3ad6faec), W64LIT(0x6c44198c4a475817)
    };

    #ifdef LITTLE_ENDIAN_ORDER
    #define blk0(i) (W[i] = ByteReverseWord64(DATA[i]))
    #else
    #define blk0(i) (W[i] = DATA[i])
    #endif

    #define blk2(i) (                \
                   W[ i         ] += \
                s1(W[(i- 2) & 15])+  \
                   W[(i- 7) & 15] +  \
                s0(W[(i-15) & 15])   \
            )

    #define Ch(x,y,z)  (z ^ ((z ^ y) & x))
    #define Maj(x,y,z) (y ^ ((y ^ z) & (x ^ y)))

    #define a(i) T[(0-i) & 7]
    #define b(i) T[(1-i) & 7]
    #define c(i) T[(2-i) & 7]
    #define d(i) T[(3-i) & 7]
    #define e(i) T[(4-i) & 7]
    #define f(i) T[(5-i) & 7]
    #define g(i) T[(6-i) & 7]
    #define h(i) T[(7-i) & 7]

    #define S0(x) (rotrFixed64(x,28) ^ rotrFixed64(x,34) ^ rotrFixed64(x,39))
    #define S1(x) (rotrFixed64(x,14) ^ rotrFixed64(x,18) ^ rotrFixed64(x,41))
    #define s0(x) (rotrFixed64(x, 1) ^ rotrFixed64(x, 8) ^ (x>>7))
    #define s1(x) (rotrFixed64(x,19) ^ rotrFixed64(x,61) ^ (x>>6))

    #define R0(i)                                                 \
        h(i) += S1(e(i)) + Ch(e(i),f(i),g(i)) + K[i+j] + blk0(i); \
        d(i) += h(i);                                             \
        h(i) += S0(a(i)) + Maj(a(i),b(i),c(i))
    #define R(i)                                                  \
        h(i) += S1(e(i)) + Ch(e(i),f(i),g(i)) + K[i+j] + blk2(i); \
        d(i) += h(i);                                             \
        h(i) += S0(a(i)) + Maj(a(i),b(i),c(i))

    #define DATA    sha512->buffer
    static void Transform_Sha512(wc_Sha512* sha512)
    {
        const word64* K = K512;
        word32 j;
        word64 T[8];
        word64 W[16];

        /* Copy digest to working vars */
        T[0] = sha512->digest[0];
        T[1] = sha512->digest[1];
        T[2] = sha512->digest[2];
        T[3] = sha512->digest[3];
        T[4] = sha512->digest[4];
        T[5] = sha512->digest[5];
        T[6] = sha512->digest[6];
        T[7] = sha512->digest[7];

        /* 80 operations, partially loop unrolled */
        j = 0;
        R0( 0); R0( 1); R0( 2); R0( 3);
        R0( 4); R0( 5); R0( 6); R0( 7);
        R0( 8); R0( 9); R0(10); R0(11);
        R0(12); R0(13); R0(14); R0(15);
        for (j = 16; j < 80; j += 16) {
            R( 0); R( 1); R( 2); R( 3);
            R( 4); R( 5); R( 6); R( 7);
            R( 8); R( 9); R(10); R(11);
            R(12); R(13); R(14); R(15);
        }

        /* Add the working vars back into digest */
        sha512->digest[0] += T[0];
        sha512->digest[1] += T[1];
        sha512->digest[2] += T[2];
        sha512->digest[3] += T[3];
        sha512->digest[4] += T[4];
        sha512->digest[5] += T[5];
        sha512->digest[6] += T[6];
        sha512->digest[7] += T[7];

        return 0;
    }
    #undef DATA

    #define DATA    ((word64*)data)
    static void Transform_Sha512_Len(wc_Sha512* sha512, const byte* data, word32 len)
    {
        const word64* K = K512;
        word32 j;
        word64 T[8];
        word64 TO[8];
        word64 W[16];

        /* Copy digest to working vars */
        T[0] = sha512->digest[0];
        T[1] = sha512->digest[1];
        T[2] = sha512->digest[2];
        T[3] = sha512->digest[3];
        T[4] = sha512->digest[4];
        T[5] = sha512->digest[5];
        T[6] = sha512->digest[6];
        T[7] = sha512->digest[7];

        do {
            TO[0] = T[0];
            TO[1] = T[1];
            TO[2] = T[2];
            TO[3] = T[3];
            TO[4] = T[4];
            TO[5] = T[5];
            TO[6] = T[6];
            TO[7] = T[7];

            /* 80 operations, partially loop unrolled */
            j = 0;
            R0( 0); R0( 1); R0( 2); R0( 3);
            R0( 4); R0( 5); R0( 6); R0( 7);
            R0( 8); R0( 9); R0(10); R0(11);
            R0(12); R0(13); R0(14); R0(15);
            for (j = 16; j < 80; j += 16) {
                R( 0); R( 1); R( 2); R( 3);
                R( 4); R( 5); R( 6); R( 7);
                R( 8); R( 9); R(10); R(11);
                R(12); R(13); R(14); R(15);
            }

            T[0] += TO[0];
            T[1] += TO[1];
            T[2] += TO[2];
            T[3] += TO[3];
            T[4] += TO[4];
            T[5] += TO[5];
            T[6] += TO[6];
            T[7] += TO[7];

            data += 128;
            len -= 128;
        }
        while (len > 0);

        /* Add the working vars back into digest */
        sha512->digest[0] = T[0];
        sha512->digest[1] = T[1];
        sha512->digest[2] = T[2];
        sha512->digest[3] = T[3];
        sha512->digest[4] = T[4];
        sha512->digest[5] = T[5];
        sha512->digest[6] = T[6];
        sha512->digest[7] = T[7];

        return 0;
    }
    #undef DATA
    #endif


    static WC_INLINE void AddLength(wc_Sha512* sha512, word32 len)
    {
        word64 tmp = sha512->loLen;
        if ( (sha512->loLen += len) < tmp)
            sha512->hiLen++;                       /* carry low to high */
    }

    static WC_INLINE int Sha512Update(wc_Sha512* sha512, const byte* data, word32 len)
    {
        int ret = 0;
        /* do block size increments */
        byte* local = (byte*)sha512->buffer;
        word32 blocksLen;

        /* check that internal buffLen is valid */
        if (sha512->buffLen >= WC_SHA512_BLOCK_SIZE)
            return BUFFER_E;

        AddLength(sha512, len);

        if (sha512->buffLen > 0) {
            word32 add = min(len, WC_SHA512_BLOCK_SIZE - sha512->buffLen);
            if (add > 0) {
                XMEMCPY(&local[sha512->buffLen], data, add);

                sha512->buffLen += add;
                data            += add;
                len             -= add;
            }

            if (sha512->buffLen == WC_SHA512_BLOCK_SIZE) {
    #ifndef WOLFSSL_ARMASM
                Transform_Sha512(sha512);
    #else
                Transform_Sha512_Len(sha512, (const byte*)sha512->buffer,
                                                              WC_SHA512_BLOCK_SIZE);
    #endif
                sha512->buffLen = 0;
            }
        }

        blocksLen = len & ~(WC_SHA512_BLOCK_SIZE-1);
        if (blocksLen > 0) {
            /* Byte reversal performed in function if required. */
            Transform_Sha512_Len(sha512, data, blocksLen);
            data += blocksLen;
            len  -= blocksLen;
        }

        if (len > 0) {
            XMEMCPY(local, data, len);
            sha512->buffLen = len;
        }

        return ret;
    }

    #ifdef WOLFSSL_SHA512

    int wc_Sha512Update(wc_Sha512* sha512, const byte* data, word32 len)
    {
        if (sha512 == NULL || (data == NULL && len > 0)) {
            return BAD_FUNC_ARG;
        }

        return Sha512Update(sha512, data, len);
    }

    #endif /* WOLFSSL_SHA512 */

    static WC_INLINE int Sha512Final(wc_Sha512* sha512)
    {
        byte* local = (byte*)sha512->buffer;

        if (sha512 == NULL) {
            return BAD_FUNC_ARG;
        }

        local[sha512->buffLen++] = 0x80;  /* add 1 */

        /* pad with zeros */
        if (sha512->buffLen > WC_SHA512_PAD_SIZE) {
            XMEMSET(&local[sha512->buffLen], 0, WC_SHA512_BLOCK_SIZE -
                                                                   sha512->buffLen);
            sha512->buffLen += WC_SHA512_BLOCK_SIZE - sha512->buffLen;
    #ifndef WOLFSSL_ARMASM
            Transform_Sha512(sha512);
    #else
            Transform_Sha512_Len(sha512, (const byte*)sha512->buffer,
                                                              WC_SHA512_BLOCK_SIZE);
    #endif

            sha512->buffLen = 0;
        }
        XMEMSET(&local[sha512->buffLen], 0, WC_SHA512_PAD_SIZE - sha512->buffLen);

        /* put lengths in bits */
        sha512->hiLen = (sha512->loLen >> (8 * sizeof(sha512->loLen) - 3)) +
                                                             (sha512->hiLen << 3);
        sha512->loLen = sha512->loLen << 3;

        /* store lengths */
        /* ! length ordering dependent on digest endian type ! */

        sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 2] = sha512->hiLen;
        sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 1] = sha512->loLen;

        ByteReverseWords64(
                       &(sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 2]),
                       &(sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 2]),
                       WC_SHA512_BLOCK_SIZE - WC_SHA512_PAD_SIZE);
    #ifndef WOLFSSL_ARMASM
        Transform_Sha512(sha512);
    #else
        Transform_Sha512_Len(sha512, (const byte*)sha512->buffer,
                                                              WC_SHA512_BLOCK_SIZE);
    #endif

    #ifdef LITTLE_ENDIAN_ORDER
        ByteReverseWords64(sha512->digest, sha512->digest, WC_SHA512_DIGEST_SIZE);
    #endif

        return 0;
    }

    #ifdef WOLFSSL_SHA512

    int wc_Sha512FinalRaw(wc_Sha512* sha512, byte* hash)
    {
    #ifdef LITTLE_ENDIAN_ORDER
        word64 digest[WC_SHA512_DIGEST_SIZE / sizeof(word64)];
    #endif

        if (sha512 == NULL || hash == NULL) {
            return BAD_FUNC_ARG;
        }

    #ifdef LITTLE_ENDIAN_ORDER
        ByteReverseWords64((word64*)digest, (word64*)sha512->digest,
                                                             WC_SHA512_DIGEST_SIZE);
        XMEMCPY(hash, digest, WC_SHA512_DIGEST_SIZE);
    #else
        XMEMCPY(hash, sha512->digest, WC_SHA512_DIGEST_SIZE);
    #endif

        return 0;
    }

    int wc_Sha512Final(wc_Sha512* sha512, byte* hash)
    {
        int ret;

        if (sha512 == NULL || hash == NULL) {
            return BAD_FUNC_ARG;
        }

        ret = Sha512Final(sha512);
        if (ret != 0)
            return ret;

        XMEMCPY(hash, sha512->digest, WC_SHA512_DIGEST_SIZE);

        return InitSha512(sha512);  /* reset state */
    }

    int wc_InitSha512(wc_Sha512* sha512)
    {
        return wc_InitSha512_ex(sha512, NULL, INVALID_DEVID);
    }

    void wc_Sha512Free(wc_Sha512* sha512)
    {
        if (sha512 == NULL)
            return;

    #ifdef WOLFSSL_SMALL_STACK_CACHE
        if (sha512->W != NULL) {
            XFREE(sha512->W, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sha512->W = NULL;
        }
    #endif
    }

    #endif /* WOLFSSL_SHA512 */

    /* -------------------------------------------------------------------------- */
    /* SHA384 */
    /* -------------------------------------------------------------------------- */
    #ifdef WOLFSSL_SHA384

    static int InitSha384(wc_Sha384* sha384)
    {
        if (sha384 == NULL) {
            return BAD_FUNC_ARG;
        }

        sha384->digest[0] = W64LIT(0xcbbb9d5dc1059ed8);
        sha384->digest[1] = W64LIT(0x629a292a367cd507);
        sha384->digest[2] = W64LIT(0x9159015a3070dd17);
        sha384->digest[3] = W64LIT(0x152fecd8f70e5939);
        sha384->digest[4] = W64LIT(0x67332667ffc00b31);
        sha384->digest[5] = W64LIT(0x8eb44a8768581511);
        sha384->digest[6] = W64LIT(0xdb0c2e0d64f98fa7);
        sha384->digest[7] = W64LIT(0x47b5481dbefa4fa4);

        sha384->buffLen = 0;
        sha384->loLen   = 0;
        sha384->hiLen   = 0;
    #if defined(WOLFSSL_HASH_FLAGS) || defined(WOLF_CRYPTO_CB)
        sha384->flags = 0;
    #endif

        return 0;
    }

    int wc_Sha384Update(wc_Sha384* sha384, const byte* data, word32 len)
    {
        if (sha384 == NULL || (data == NULL && len > 0)) {
            return BAD_FUNC_ARG;
        }

        return Sha512Update((wc_Sha512*)sha384, data, len);
    }


    int wc_Sha384FinalRaw(wc_Sha384* sha384, byte* hash)
    {
    #ifdef LITTLE_ENDIAN_ORDER
        word64 digest[WC_SHA384_DIGEST_SIZE / sizeof(word64)];
    #endif

        if (sha384 == NULL || hash == NULL) {
            return BAD_FUNC_ARG;
        }

    #ifdef LITTLE_ENDIAN_ORDER
        ByteReverseWords64((word64*)digest, (word64*)sha384->digest,
                                                             WC_SHA384_DIGEST_SIZE);
        XMEMCPY(hash, digest, WC_SHA384_DIGEST_SIZE);
    #else
        XMEMCPY(hash, sha384->digest, WC_SHA384_DIGEST_SIZE);
    #endif

        return 0;
    }

    int wc_Sha384Final(wc_Sha384* sha384, byte* hash)
    {
        int ret;

        if (sha384 == NULL || hash == NULL) {
            return BAD_FUNC_ARG;
        }

        ret = Sha512Final((wc_Sha512*)sha384);
        if (ret != 0)
            return ret;

        XMEMCPY(hash, sha384->digest, WC_SHA384_DIGEST_SIZE);

        return InitSha384(sha384);  /* reset state */
    }

    int wc_InitSha384_ex(wc_Sha384* sha384, void* heap, int devId)
    {
        int ret;

        if (sha384 == NULL) {
            return BAD_FUNC_ARG;
        }

        sha384->heap = heap;
        ret = InitSha384(sha384);
        if (ret != 0)
            return ret;

    #ifdef WOLFSSL_SMALL_STACK_CACHE
        sha384->W = NULL;
    #endif

        (void)devId;

        return ret;
    }

    int wc_InitSha384(wc_Sha384* sha384)
    {
        return wc_InitSha384_ex(sha384, NULL, INVALID_DEVID);
    }

    void wc_Sha384Free(wc_Sha384* sha384)
    {
        if (sha384 == NULL)
            return;

    #ifdef WOLFSSL_SMALL_STACK_CACHE
        if (sha384->W != NULL) {
            XFREE(sha384->W, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sha384->W = NULL;
        }
    #endif
    }

    #endif /* WOLFSSL_SHA384 */

    #ifdef WOLFSSL_SHA512

    int wc_Sha512GetHash(wc_Sha512* sha512, byte* hash)
    {
        int ret;
        wc_Sha512 tmpSha512;

        if (sha512 == NULL || hash == NULL)
            return BAD_FUNC_ARG;

        ret = wc_Sha512Copy(sha512, &tmpSha512);
        if (ret == 0) {
            ret = wc_Sha512Final(&tmpSha512, hash);
            wc_Sha512Free(&tmpSha512);
        }
        return ret;
    }

    int wc_Sha512Copy(wc_Sha512* src, wc_Sha512* dst)
    {
        int ret = 0;

        if (src == NULL || dst == NULL)
            return BAD_FUNC_ARG;

        XMEMCPY(dst, src, sizeof(wc_Sha512));
    #ifdef WOLFSSL_SMALL_STACK_CACHE
        dst->W = NULL;
    #endif

    #if defined(WOLFSSL_HASH_FLAGS) || defined(WOLF_CRYPTO_CB)
         dst->flags |= WC_HASH_FLAG_ISCOPY;
    #endif

        return ret;
    }

    #if defined(WOLFSSL_HASH_FLAGS) || defined(WOLF_CRYPTO_CB)
    int wc_Sha512SetFlags(wc_Sha512* sha512, word32 flags)
    {
        if (sha512) {
            sha512->flags = flags;
        }
        return 0;
    }
    int wc_Sha512GetFlags(wc_Sha512* sha512, word32* flags)
    {
        if (sha512 && flags) {
            *flags = sha512->flags;
        }
        return 0;
    }
    #endif

    #endif /* WOLFSSL_SHA512 */

    #ifdef WOLFSSL_SHA384

    int wc_Sha384GetHash(wc_Sha384* sha384, byte* hash)
    {
        int ret;
        wc_Sha384 tmpSha384;

        if (sha384 == NULL || hash == NULL)
            return BAD_FUNC_ARG;
        ret = wc_Sha384Copy(sha384, &tmpSha384);
        if (ret == 0) {
            ret = wc_Sha384Final(&tmpSha384, hash);
            wc_Sha384Free(&tmpSha384);
        }
        return ret;
    }
    int wc_Sha384Copy(wc_Sha384* src, wc_Sha384* dst)
    {
        int ret = 0;

        if (src == NULL || dst == NULL)
            return BAD_FUNC_ARG;

        XMEMCPY(dst, src, sizeof(wc_Sha384));
    #ifdef WOLFSSL_SMALL_STACK_CACHE
        dst->W = NULL;
    #endif

    #if defined(WOLFSSL_HASH_FLAGS) || defined(WOLF_CRYPTO_CB)
         dst->flags |= WC_HASH_FLAG_ISCOPY;
    #endif

        return ret;
    }

    #if defined(WOLFSSL_HASH_FLAGS) || defined(WOLF_CRYPTO_CB)
    int wc_Sha384SetFlags(wc_Sha384* sha384, word32 flags)
    {
        if (sha384) {
            sha384->flags = flags;
        }
        return 0;
    }
    int wc_Sha384GetFlags(wc_Sha384* sha384, word32* flags)
    {
        if (sha384 && flags) {
            *flags = sha384->flags;
        }
        return 0;
    }
    #endif

    #endif /* WOLFSSL_SHA384 */

    #endif /* WOLFSSL_SHA512 || WOLFSSL_SHA384 */
    #endif /* WOLFSSL_ARMASM */
    /* end of: armv8-sha512 */

#else /* HAVE_FIPS && HAVE_FIPS_VERSION >= 2 && WOLFSSL_ARMASM */

#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cpuid.h>

/* deprecated USE_SLOW_SHA2 (replaced with USE_SLOW_SHA512) */
#if defined(USE_SLOW_SHA2) && !defined(USE_SLOW_SHA512)
    #define USE_SLOW_SHA512
#endif

/* fips wrapper calls, user can call direct */
#if defined(HAVE_FIPS) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 2))

    int wc_InitSha512(wc_Sha512* sha)
    {
        if (sha == NULL) {
            return BAD_FUNC_ARG;
        }

        return InitSha512_fips(sha);
    }
    int wc_InitSha512_ex(wc_Sha512* sha, void* heap, int devId)
    {
        (void)heap;
        (void)devId;
        if (sha == NULL) {
            return BAD_FUNC_ARG;
        }
        return InitSha512_fips(sha);
    }
    int wc_Sha512Update(wc_Sha512* sha, const byte* data, word32 len)
    {
        if (sha == NULL || (data == NULL && len > 0)) {
            return BAD_FUNC_ARG;
        }

        return Sha512Update_fips(sha, data, len);
    }
    int wc_Sha512Final(wc_Sha512* sha, byte* out)
    {
        if (sha == NULL || out == NULL) {
            return BAD_FUNC_ARG;
        }

        return Sha512Final_fips(sha, out);
    }
    void wc_Sha512Free(wc_Sha512* sha)
    {
        (void)sha;
        /* Not supported in FIPS */
    }

    #if defined(WOLFSSL_SHA384) || defined(HAVE_AESGCM)
        int wc_InitSha384(wc_Sha384* sha)
        {
            if (sha == NULL) {
                return BAD_FUNC_ARG;
            }
            return InitSha384_fips(sha);
        }
        int wc_InitSha384_ex(wc_Sha384* sha, void* heap, int devId)
        {
            (void)heap;
            (void)devId;
            if (sha == NULL) {
                return BAD_FUNC_ARG;
            }
            return InitSha384_fips(sha);
        }
        int wc_Sha384Update(wc_Sha384* sha, const byte* data, word32 len)
        {
            if (sha == NULL || (data == NULL && len > 0)) {
                return BAD_FUNC_ARG;
            }
            return Sha384Update_fips(sha, data, len);
        }
        int wc_Sha384Final(wc_Sha384* sha, byte* out)
        {
            if (sha == NULL || out == NULL) {
                return BAD_FUNC_ARG;
            }
            return Sha384Final_fips(sha, out);
        }
        void wc_Sha384Free(wc_Sha384* sha)
        {
            (void)sha;
            /* Not supported in FIPS */
        }
    #endif /* WOLFSSL_SHA384 || HAVE_AESGCM */

#else /* else build without fips, or for FIPS v2 */

#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif


#if defined(USE_INTEL_SPEEDUP)
    #define HAVE_INTEL_AVX1

    #if defined(__GNUC__) && ((__GNUC__ < 4) || \
                              (__GNUC__ == 4 && __GNUC_MINOR__ <= 8))
        #define NO_AVX2_SUPPORT
    #endif
    #if defined(__clang__) && ((__clang_major__ < 3) || \
                               (__clang_major__ == 3 && __clang_minor__ <= 5))
        #define NO_AVX2_SUPPORT
    #elif defined(__clang__) && defined(NO_AVX2_SUPPORT)
        #undef NO_AVX2_SUPPORT
    #endif

    #define HAVE_INTEL_AVX1
    #ifndef NO_AVX2_SUPPORT
        #define HAVE_INTEL_AVX2
    #endif
#endif

#if defined(HAVE_INTEL_AVX1)
    /* #define DEBUG_XMM  */
#endif

#if defined(HAVE_INTEL_AVX2)
    #define HAVE_INTEL_RORX
    /* #define DEBUG_YMM  */
#endif

#if defined(HAVE_BYTEREVERSE64) && \
        !defined(HAVE_INTEL_AVX1) && !defined(HAVE_INTEL_AVX2)
    #define ByteReverseWords64(out, in, size) ByteReverseWords64_1(out, size)
    #define ByteReverseWords64_1(buf, size) \
        { unsigned int i ;\
            for(i=0; i< size/sizeof(word64); i++){\
                __asm__ volatile("bswapq %0":"+r"(buf[i])::) ;\
            }\
        }
#endif

#if defined(WOLFSSL_IMX6_CAAM) && !defined(NO_IMX6_CAAM_HASH)
    /* functions defined in wolfcrypt/src/port/caam/caam_sha.c */
#else

static int InitSha512(wc_Sha512* sha512)
{
    if (sha512 == NULL)
        return BAD_FUNC_ARG;

    sha512->digest[0] = W64LIT(0x6a09e667f3bcc908);
    sha512->digest[1] = W64LIT(0xbb67ae8584caa73b);
    sha512->digest[2] = W64LIT(0x3c6ef372fe94f82b);
    sha512->digest[3] = W64LIT(0xa54ff53a5f1d36f1);
    sha512->digest[4] = W64LIT(0x510e527fade682d1);
    sha512->digest[5] = W64LIT(0x9b05688c2b3e6c1f);
    sha512->digest[6] = W64LIT(0x1f83d9abfb41bd6b);
    sha512->digest[7] = W64LIT(0x5be0cd19137e2179);

    sha512->buffLen = 0;
    sha512->loLen   = 0;
    sha512->hiLen   = 0;

    return 0;
}


/* Hardware Acceleration */
#if defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2)

    /*****
    Intel AVX1/AVX2 Macro Control Structure

    #if defined(HAVE_INteL_SPEEDUP)
        #define HAVE_INTEL_AVX1
        #define HAVE_INTEL_AVX2
    #endif

    int InitSha512(wc_Sha512* sha512) {
         Save/Recover XMM, YMM
         ...

         Check Intel AVX cpuid flags
    }

    #if defined(HAVE_INTEL_AVX1)|| defined(HAVE_INTEL_AVX2)
      Transform_Sha512_AVX1(); # Function prototype
      Transform_Sha512_AVX2(); #
    #endif

      _Transform_Sha512() {     # Native Transform Function body

      }

      int Sha512Update() {
         Save/Recover XMM, YMM
         ...
      }

      int Sha512Final() {
         Save/Recover XMM, YMM
         ...
      }


    #if defined(HAVE_INTEL_AVX1)

       XMM Instructions/INLINE asm Definitions

    #endif

    #if defined(HAVE_INTEL_AVX2)

       YMM Instructions/INLINE asm Definitions

    #endif

    #if defnied(HAVE_INTEL_AVX1)

      int Transform_Sha512_AVX1() {
          Stitched Message Sched/Round
      }

    #endif

    #if defnied(HAVE_INTEL_AVX2)

      int Transform_Sha512_AVX2() {
          Stitched Message Sched/Round
      }
    #endif

    */


    /* Each platform needs to query info type 1 from cpuid to see if aesni is
     * supported. Also, let's setup a macro for proper linkage w/o ABI conflicts
     */

    #if defined(HAVE_INTEL_AVX1)
        static int Transform_Sha512_AVX1(wc_Sha512 *sha512);
        static int Transform_Sha512_AVX1_Len(wc_Sha512 *sha512, word32 len);
    #endif
    #if defined(HAVE_INTEL_AVX2)
        static int Transform_Sha512_AVX2(wc_Sha512 *sha512);
        static int Transform_Sha512_AVX2_Len(wc_Sha512 *sha512, word32 len);
        #if defined(HAVE_INTEL_RORX)
            static int Transform_Sha512_AVX1_RORX(wc_Sha512 *sha512);
            static int Transform_Sha512_AVX1_RORX_Len(wc_Sha512 *sha512,
                                                      word32 len);
            static int Transform_Sha512_AVX2_RORX(wc_Sha512 *sha512);
            static int Transform_Sha512_AVX2_RORX_Len(wc_Sha512 *sha512,
                                                      word32 len);
        #endif
    #endif
    static int _Transform_Sha512(wc_Sha512 *sha512);
    static int (*Transform_Sha512_p)(wc_Sha512* sha512) = _Transform_Sha512;
    static int (*Transform_Sha512_Len_p)(wc_Sha512* sha512, word32 len) = NULL;
    static int transform_check = 0;
    static int intel_flags;
    #define Transform_Sha512(sha512)     (*Transform_Sha512_p)(sha512)
    #define Transform_Sha512_Len(sha512, len) \
        (*Transform_Sha512_Len_p)(sha512, len)

    static void Sha512_SetTransform()
    {
        if (transform_check)
            return;

        intel_flags = cpuid_get_flags();

    #if defined(HAVE_INTEL_AVX2)
        if (IS_INTEL_AVX2(intel_flags)) {
        #ifdef HAVE_INTEL_RORX
            if (IS_INTEL_BMI2(intel_flags)) {
                Transform_Sha512_p = Transform_Sha512_AVX2_RORX;
                Transform_Sha512_Len_p = Transform_Sha512_AVX2_RORX_Len;
            }
            else
        #endif
            if (1) {
                Transform_Sha512_p = Transform_Sha512_AVX2;
                Transform_Sha512_Len_p = Transform_Sha512_AVX2_Len;
            }
        #ifdef HAVE_INTEL_RORX
            else {
                Transform_Sha512_p = Transform_Sha512_AVX1_RORX;
                Transform_Sha512_Len_p = Transform_Sha512_AVX1_RORX_Len;
            }
        #endif
        }
        else
    #endif
    #if defined(HAVE_INTEL_AVX1)
        if (IS_INTEL_AVX1(intel_flags)) {
            Transform_Sha512_p = Transform_Sha512_AVX1;
            Transform_Sha512_Len_p = Transform_Sha512_AVX1_Len;
        }
        else
    #endif
            Transform_Sha512_p = _Transform_Sha512;

        transform_check = 1;
    }

    int wc_InitSha512_ex(wc_Sha512* sha512, void* heap, int devId)
    {
        int ret = InitSha512(sha512);

        (void)heap;
        (void)devId;

        Sha512_SetTransform();

        return ret;
    }

#else
    #define Transform_Sha512(sha512) _Transform_Sha512(sha512)

    int wc_InitSha512_ex(wc_Sha512* sha512, void* heap, int devId)
    {
        int ret = 0;

        if (sha512 == NULL)
            return BAD_FUNC_ARG;

        sha512->heap = heap;

        ret = InitSha512(sha512);
        if (ret != 0)
            return ret;

    #if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA512)
        ret = wolfAsync_DevCtxInit(&sha512->asyncDev,
                            WOLFSSL_ASYNC_MARKER_SHA512, sha512->heap, devId);
    #else
        (void)devId;
    #endif /* WOLFSSL_ASYNC_CRYPT */

        return ret;
    }

#endif /* Hardware Acceleration */

static const word64 K512[80] = {
    W64LIT(0x428a2f98d728ae22), W64LIT(0x7137449123ef65cd),
    W64LIT(0xb5c0fbcfec4d3b2f), W64LIT(0xe9b5dba58189dbbc),
    W64LIT(0x3956c25bf348b538), W64LIT(0x59f111f1b605d019),
    W64LIT(0x923f82a4af194f9b), W64LIT(0xab1c5ed5da6d8118),
    W64LIT(0xd807aa98a3030242), W64LIT(0x12835b0145706fbe),
    W64LIT(0x243185be4ee4b28c), W64LIT(0x550c7dc3d5ffb4e2),
    W64LIT(0x72be5d74f27b896f), W64LIT(0x80deb1fe3b1696b1),
    W64LIT(0x9bdc06a725c71235), W64LIT(0xc19bf174cf692694),
    W64LIT(0xe49b69c19ef14ad2), W64LIT(0xefbe4786384f25e3),
    W64LIT(0x0fc19dc68b8cd5b5), W64LIT(0x240ca1cc77ac9c65),
    W64LIT(0x2de92c6f592b0275), W64LIT(0x4a7484aa6ea6e483),
    W64LIT(0x5cb0a9dcbd41fbd4), W64LIT(0x76f988da831153b5),
    W64LIT(0x983e5152ee66dfab), W64LIT(0xa831c66d2db43210),
    W64LIT(0xb00327c898fb213f), W64LIT(0xbf597fc7beef0ee4),
    W64LIT(0xc6e00bf33da88fc2), W64LIT(0xd5a79147930aa725),
    W64LIT(0x06ca6351e003826f), W64LIT(0x142929670a0e6e70),
    W64LIT(0x27b70a8546d22ffc), W64LIT(0x2e1b21385c26c926),
    W64LIT(0x4d2c6dfc5ac42aed), W64LIT(0x53380d139d95b3df),
    W64LIT(0x650a73548baf63de), W64LIT(0x766a0abb3c77b2a8),
    W64LIT(0x81c2c92e47edaee6), W64LIT(0x92722c851482353b),
    W64LIT(0xa2bfe8a14cf10364), W64LIT(0xa81a664bbc423001),
    W64LIT(0xc24b8b70d0f89791), W64LIT(0xc76c51a30654be30),
    W64LIT(0xd192e819d6ef5218), W64LIT(0xd69906245565a910),
    W64LIT(0xf40e35855771202a), W64LIT(0x106aa07032bbd1b8),
    W64LIT(0x19a4c116b8d2d0c8), W64LIT(0x1e376c085141ab53),
    W64LIT(0x2748774cdf8eeb99), W64LIT(0x34b0bcb5e19b48a8),
    W64LIT(0x391c0cb3c5c95a63), W64LIT(0x4ed8aa4ae3418acb),
    W64LIT(0x5b9cca4f7763e373), W64LIT(0x682e6ff3d6b2b8a3),
    W64LIT(0x748f82ee5defb2fc), W64LIT(0x78a5636f43172f60),
    W64LIT(0x84c87814a1f0ab72), W64LIT(0x8cc702081a6439ec),
    W64LIT(0x90befffa23631e28), W64LIT(0xa4506cebde82bde9),
    W64LIT(0xbef9a3f7b2c67915), W64LIT(0xc67178f2e372532b),
    W64LIT(0xca273eceea26619c), W64LIT(0xd186b8c721c0c207),
    W64LIT(0xeada7dd6cde0eb1e), W64LIT(0xf57d4f7fee6ed178),
    W64LIT(0x06f067aa72176fba), W64LIT(0x0a637dc5a2c898a6),
    W64LIT(0x113f9804bef90dae), W64LIT(0x1b710b35131c471b),
    W64LIT(0x28db77f523047d84), W64LIT(0x32caab7b40c72493),
    W64LIT(0x3c9ebe0a15c9bebc), W64LIT(0x431d67c49c100d4c),
    W64LIT(0x4cc5d4becb3e42b6), W64LIT(0x597f299cfc657e2a),
    W64LIT(0x5fcb6fab3ad6faec), W64LIT(0x6c44198c4a475817)
};

#define blk0(i) (W[i] = sha512->buffer[i])

#define blk2(i) (\
               W[ i     & 15] += \
            s1(W[(i-2)  & 15])+ \
               W[(i-7)  & 15] + \
            s0(W[(i-15) & 15])  \
        )

#define Ch(x,y,z)  (z ^ (x & (y ^ z)))
#define Maj(x,y,z) ((x & y) | (z & (x | y)))

#define a(i) T[(0-i) & 7]
#define b(i) T[(1-i) & 7]
#define c(i) T[(2-i) & 7]
#define d(i) T[(3-i) & 7]
#define e(i) T[(4-i) & 7]
#define f(i) T[(5-i) & 7]
#define g(i) T[(6-i) & 7]
#define h(i) T[(7-i) & 7]

#define S0(x) (rotrFixed64(x,28) ^ rotrFixed64(x,34) ^ rotrFixed64(x,39))
#define S1(x) (rotrFixed64(x,14) ^ rotrFixed64(x,18) ^ rotrFixed64(x,41))
#define s0(x) (rotrFixed64(x,1)  ^ rotrFixed64(x,8)  ^ (x>>7))
#define s1(x) (rotrFixed64(x,19) ^ rotrFixed64(x,61) ^ (x>>6))

#define R(i) \
    h(i) += S1(e(i)) + Ch(e(i),f(i),g(i)) + K[i+j] + (j ? blk2(i) : blk0(i)); \
    d(i) += h(i); \
    h(i) += S0(a(i)) + Maj(a(i),b(i),c(i))

static int _Transform_Sha512(wc_Sha512* sha512)
{
    const word64* K = K512;
    word32 j;
    word64 T[8];

#ifdef WOLFSSL_SMALL_STACK
    word64* W;
    W = (word64*) XMALLOC(sizeof(word64) * 16, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (W == NULL)
        return MEMORY_E;
#else
    word64 W[16];
#endif

    /* Copy digest to working vars */
    XMEMCPY(T, sha512->digest, sizeof(T));

#ifdef USE_SLOW_SHA512
    /* over twice as small, but 50% slower */
    /* 80 operations, not unrolled */
    for (j = 0; j < 80; j += 16) {
        int m;
        for (m = 0; m < 16; m++) { /* braces needed here for macros {} */
            R(m);
        }
    }
#else
    /* 80 operations, partially loop unrolled */
    for (j = 0; j < 80; j += 16) {
        R( 0); R( 1); R( 2); R( 3);
        R( 4); R( 5); R( 6); R( 7);
        R( 8); R( 9); R(10); R(11);
        R(12); R(13); R(14); R(15);
    }
#endif /* USE_SLOW_SHA512 */

    /* Add the working vars back into digest */
    sha512->digest[0] += a(0);
    sha512->digest[1] += b(0);
    sha512->digest[2] += c(0);
    sha512->digest[3] += d(0);
    sha512->digest[4] += e(0);
    sha512->digest[5] += f(0);
    sha512->digest[6] += g(0);
    sha512->digest[7] += h(0);

    /* Wipe variables */
    ForceZero(W, sizeof(word64) * 16);
    ForceZero(T, sizeof(T));

#ifdef WOLFSSL_SMALL_STACK
    XFREE(W, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return 0;
}


static INLINE void AddLength(wc_Sha512* sha512, word32 len)
{
    word64 tmp = sha512->loLen;
    if ( (sha512->loLen += len) < tmp)
        sha512->hiLen++;                       /* carry low to high */
}

static INLINE int Sha512Update(wc_Sha512* sha512, const byte* data, word32 len)
{
    int ret = 0;
    /* do block size increments */
    byte* local = (byte*)sha512->buffer;

    /* check that internal buffLen is valid */
    if (sha512->buffLen >= WC_SHA512_BLOCK_SIZE)
        return BUFFER_E;

    if (sha512->buffLen > 0) {
        word32 add = min(len, WC_SHA512_BLOCK_SIZE - sha512->buffLen);
        XMEMCPY(&local[sha512->buffLen], data, add);

        sha512->buffLen += add;
        data            += add;
        len             -= add;

        if (sha512->buffLen == WC_SHA512_BLOCK_SIZE) {
    #if defined(LITTLE_ENDIAN_ORDER)
        #if defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2)
            if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
        #endif
            {
                ByteReverseWords64(sha512->buffer, sha512->buffer,
                                                          WC_SHA512_BLOCK_SIZE);
            }
    #endif
            ret = Transform_Sha512(sha512);
            if (ret == 0) {
                AddLength(sha512, WC_SHA512_BLOCK_SIZE);
                sha512->buffLen = 0;
            }
            else
                len = 0;
        }
    }

#if defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2)
    if (Transform_Sha512_Len_p != NULL) {
        word32 blocksLen = len & ~(WC_SHA512_BLOCK_SIZE-1);

        if (blocksLen > 0) {
            AddLength(sha512, blocksLen);
            sha512->data = data;
            /* Byte reversal performed in function if required. */
            Transform_Sha512_Len(sha512, blocksLen);
            data += blocksLen;
            len  -= blocksLen;
        }
    }
    else
#endif
#if !defined(LITTLE_ENDIAN_ORDER) || defined(FREESCALE_MMCAU_SHA) || \
                            defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2)
    {
        word32 blocksLen = len & ~(WC_SHA512_BLOCK_SIZE-1);

        AddLength(sha512, blocksLen);
        while (len >= WC_SHA512_BLOCK_SIZE) {
            XMEMCPY(local, data, WC_SHA512_BLOCK_SIZE);

            data += WC_SHA512_BLOCK_SIZE;
            len  -= WC_SHA512_BLOCK_SIZE;

            /* Byte reversal performed in function if required. */
            ret = Transform_Sha512(sha512);
            if (ret != 0)
                break;
        }
    }
#else
    {
        word32 blocksLen = len & ~(WC_SHA512_BLOCK_SIZE-1);

        AddLength(sha512, blocksLen);
        while (len >= WC_SHA512_BLOCK_SIZE) {
            XMEMCPY(local, data, WC_SHA512_BLOCK_SIZE);

            data += WC_SHA512_BLOCK_SIZE;
            len  -= WC_SHA512_BLOCK_SIZE;

            ByteReverseWords64(sha512->buffer, sha512->buffer,
                                                          WC_SHA512_BLOCK_SIZE);
            ret = Transform_Sha512(sha512);
            if (ret != 0)
                break;
        }
    }
#endif

    if (len > 0) {
        XMEMCPY(local, data, len);
        sha512->buffLen = len;
    }

    return ret;
}

int wc_Sha512Update(wc_Sha512* sha512, const byte* data, word32 len)
{
    if (sha512 == NULL || (data == NULL && len > 0)) {
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA512)
    if (sha512->asyncDev.marker == WOLFSSL_ASYNC_MARKER_SHA512) {
    #if defined(HAVE_INTEL_QA)
        return IntelQaSymSha512(&sha512->asyncDev, NULL, data, len);
    #endif
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    return Sha512Update(sha512, data, len);
}
#endif /* WOLFSSL_IMX6_CAAM */

static INLINE int Sha512Final(wc_Sha512* sha512)
{
    byte* local = (byte*)sha512->buffer;
    int ret;

    if (sha512 == NULL) {
        return BAD_FUNC_ARG;
    }

    AddLength(sha512, sha512->buffLen);               /* before adding pads */

    local[sha512->buffLen++] = 0x80;  /* add 1 */

    /* pad with zeros */
    if (sha512->buffLen > WC_SHA512_PAD_SIZE) {
        XMEMSET(&local[sha512->buffLen], 0, WC_SHA512_BLOCK_SIZE - sha512->buffLen);
        sha512->buffLen += WC_SHA512_BLOCK_SIZE - sha512->buffLen;
#if defined(LITTLE_ENDIAN_ORDER)
    #if defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2)
        if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
    #endif
        {
            ByteReverseWords64(sha512->buffer,sha512->buffer,
                                                             WC_SHA512_BLOCK_SIZE);
        }
#endif /* LITTLE_ENDIAN_ORDER */
        ret = Transform_Sha512(sha512);
        if (ret != 0)
            return ret;

        sha512->buffLen = 0;
    }
    XMEMSET(&local[sha512->buffLen], 0, WC_SHA512_PAD_SIZE - sha512->buffLen);

    /* put lengths in bits */
    sha512->hiLen = (sha512->loLen >> (8 * sizeof(sha512->loLen) - 3)) +
                                                         (sha512->hiLen << 3);
    sha512->loLen = sha512->loLen << 3;

    /* store lengths */
#if defined(LITTLE_ENDIAN_ORDER)
    #if defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2)
        if (!IS_INTEL_AVX1(intel_flags) && !IS_INTEL_AVX2(intel_flags))
    #endif
            ByteReverseWords64(sha512->buffer, sha512->buffer, WC_SHA512_PAD_SIZE);
#endif
    /* ! length ordering dependent on digest endian type ! */

    sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 2] = sha512->hiLen;
    sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 1] = sha512->loLen;
#if defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2)
    if (IS_INTEL_AVX1(intel_flags) || IS_INTEL_AVX2(intel_flags))
        ByteReverseWords64(&(sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 2]),
                           &(sha512->buffer[WC_SHA512_BLOCK_SIZE / sizeof(word64) - 2]),
                           WC_SHA512_BLOCK_SIZE - WC_SHA512_PAD_SIZE);
#endif
    ret = Transform_Sha512(sha512);
    if (ret != 0)
        return ret;

    #ifdef LITTLE_ENDIAN_ORDER
        ByteReverseWords64(sha512->digest, sha512->digest, WC_SHA512_DIGEST_SIZE);
    #endif

    return 0;
}

int wc_Sha512Final(wc_Sha512* sha512, byte* hash)
{
    int ret;

    if (sha512 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA512)
    if (sha512->asyncDev.marker == WOLFSSL_ASYNC_MARKER_SHA512) {
    #if defined(HAVE_INTEL_QA)
        return IntelQaSymSha512(&sha512->asyncDev, hash, NULL,
                                            WC_SHA512_DIGEST_SIZE);
    #endif
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    ret = Sha512Final(sha512);
    if (ret != 0)
        return ret;

    XMEMCPY(hash, sha512->digest, WC_SHA512_DIGEST_SIZE);

    return InitSha512(sha512);  /* reset state */
}


int wc_InitSha512(wc_Sha512* sha512)
{
    return wc_InitSha512_ex(sha512, NULL, INVALID_DEVID);
}

void wc_Sha512Free(wc_Sha512* sha512)
{
    if (sha512 == NULL)
        return;

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA512)
    wolfAsync_DevCtxFree(&sha512->asyncDev, WOLFSSL_ASYNC_MARKER_SHA512);
#endif /* WOLFSSL_ASYNC_CRYPT */
}


#if defined(HAVE_INTEL_AVX1)

static word64 mBYTE_FLIP_MASK[] =  { 0x0001020304050607, 0x08090a0b0c0d0e0f };

#define W_0     xmm0
#define W_2     xmm1
#define W_4     xmm2
#define W_6     xmm3
#define W_8     xmm4
#define W_10    xmm5
#define W_12    xmm6
#define W_14    xmm7

#define W_M15   xmm12
#define W_M7    xmm13
#define MASK    xmm14

#define XTMP1   xmm8
#define XTMP2   xmm9
#define XTMP3   xmm10
#define XTMP4   xmm11

#define XMM_REGS \
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",       \
    "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"

#define _VPALIGNR(dest, src1, src2, bits)                       \
    "vpalignr	$"#bits", %%"#src2", %%"#src1", %%"#dest"\n\t"
#define VPALIGNR(dest, src1, src2, bits) \
       _VPALIGNR(dest, src1, src2, bits)

#define _V_SHIFT_R(dest, src, bits)                             \
    "vpsrlq	$"#bits", %%"#src", %%"#dest"\n\t"
#define V_SHIFT_R(dest, src, bits) \
       _V_SHIFT_R(dest, src, bits)

#define _V_SHIFT_L(dest, src, bits)                             \
    "vpsllq	$"#bits", %%"#src", %%"#dest"\n\t"
#define V_SHIFT_L(dest, src, bits) \
       _V_SHIFT_L(dest, src, bits)

#define _V_ADD(dest, src1, src2)                                \
    "vpaddq	%%"#src1", %%"#src2", %%"#dest"\n\t"
#define V_ADD(dest, src1, src2) \
       _V_ADD(dest, src1, src2)

#define _V_XOR(dest, src1, src2)                                \
    "vpxor	%%"#src1", %%"#src2", %%"#dest"\n\t"
#define V_XOR(dest, src1, src2) \
       _V_XOR(dest, src1, src2)

#define _V_OR(dest, src1, src2)                                 \
    "vpor	%%"#src1", %%"#src2", %%"#dest"\n\t"
#define V_OR(dest, src1, src2) \
       _V_OR(dest, src1, src2)

#define RA  %%r8
#define RB  %%r9
#define RC  %%r10
#define RD  %%r11
#define RE  %%r12
#define RF  %%r13
#define RG  %%r14
#define RH  %%r15

#define STATE_REGS "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"

#define L1  "%%rax"
#define L2  "%%rcx"
#define L3  "%%rdx"
#define L4  "%%rbx"
#define WX  "%%rsp"

#define WORK_REGS "rax", "rbx", "rcx", "rdx"

#define RND_0_1(a,b,c,d,e,f,g,h,i)                   \
    /* L1 = e >>> 23 */                              \
    "rorq	 $23, "L1"\n\t"                      \

#define RND_0_2(a,b,c,d,e,f,g,h,i)                   \
    /* L3 = a */                                     \
    "movq	"#a", "L3"\n\t"                      \
    /* L2 = f */                                     \
    "movq	"#f", "L2"\n\t"                      \
    /* h += W_X[i] */                                \
    "addq	("#i")*8("WX"), "#h"\n\t"            \
    /* L2 = f ^ g */                                 \
    "xorq	"#g", "L2"\n\t"                      \

#define RND_0_2_A(a,b,c,d,e,f,g,h,i)                 \
    /* L3 = a */                                     \
    "movq	"#a", "L3"\n\t"                      \
    /* L2 = f */                                     \
    "movq	"#f", "L2"\n\t"                      \

#define RND_0_2_B(a,b,c,d,e,f,g,h,i)                 \
    /* h += W_X[i] */                                \
    "addq	("#i")*8("WX"), "#h"\n\t"            \
    /* L2 = f ^ g */                                 \
    "xorq	"#g", "L2"\n\t"                      \

#define RND_0_3(a,b,c,d,e,f,g,h,i)                   \
    /* L1 = (e >>> 23) ^ e */                        \
    "xorq	"#e", "L1"\n\t"                      \
    /* L2 = (f ^ g) & e */                           \
    "andq	"#e", "L2"\n\t"                      \

#define RND_0_4(a,b,c,d,e,f,g,h,i)                   \
    /* L1 = ((e >>> 23) ^ e) >>> 4 */                \
    "rorq	 $4, "L1"\n\t"                       \
    /* L2 = ((f ^ g) & e) ^ g */                     \
    "xorq	"#g", "L2"\n\t"                      \

#define RND_0_5(a,b,c,d,e,f,g,h,i)                   \
    /* L1 = (((e >>> 23) ^ e) >>> 4) ^ e */          \
    "xorq	"#e", "L1"\n\t"                      \
    /* h += Ch(e,f,g) */                             \
    "addq	"L2", "#h"\n\t"                      \

#define RND_0_6(a,b,c,d,e,f,g,h,i)                   \
    /* L1 = ((((e >>> 23) ^ e) >>> 4) ^ e) >>> 14 */ \
    "rorq	$14, "L1"\n\t"                       \
    /* L3 = a ^ b */                                 \
    "xorq	"#b", "L3"\n\t"                      \

#define RND_0_7(a,b,c,d,e,f,g,h,i)                   \
    /* h += Sigma1(e) */                             \
    "addq	"L1", "#h"\n\t"                      \
    /* L2 = a */                                     \
    "movq	"#a", "L2"\n\t"                      \

#define RND_0_8(a,b,c,d,e,f,g,h,i)                   \
    /* L4 = (a ^ b) & (b ^ c) */                     \
    "andq	"L3", "L4"\n\t"                      \
    /* L2 = a >>> 5 */                               \
    "rorq	$5, "L2"\n\t"                        \

#define RND_0_9(a,b,c,d,e,f,g,h,i)                   \
    /* L2 = (a >>> 5) ^ a */                         \
    "xorq	"#a", "L2"\n\t"                      \
    /* L4 = ((a ^ b) & (b ^ c) ^ b */                \
    "xorq	"#b", "L4"\n\t"                      \

#define RND_0_10(a,b,c,d,e,f,g,h,i)                  \
    /* L2 = ((a >>> 5) ^ a) >>> 6 */                 \
    "rorq	 $6, "L2"\n\t"                       \
    /* d += h */                                     \
    "addq	"#h", "#d"\n\t"                      \

#define RND_0_11(a,b,c,d,e,f,g,h,i)                  \
    /* L2 = (((a >>> 5) ^ a) >>> 6) ^ a */           \
    "xorq	"#a", "L2"\n\t"                      \
    /* h += Sigma0(a) */                             \
    "addq	"L4", "#h"\n\t"                      \

#define RND_0_12(a,b,c,d,e,f,g,h,i)                  \
    /* L2 = ((((a >>> 5) ^ a) >>> 6) ^ a) >>> 28 */  \
    "rorq	$28, "L2"\n\t"                       \
    /* d (= e next RND) */                           \
    "movq	"#d", "L1"\n\t"                      \
    /* h += Maj(a,b,c) */                            \
    "addq	"L2", "#h"\n\t"                      \

#define RND_1_1(a,b,c,d,e,f,g,h,i)                   \
    /* L1 = e >>> 23 */                              \
    "rorq	 $23, "L1"\n\t"                      \

#define RND_1_2(a,b,c,d,e,f,g,h,i)                   \
    /* L4 = a */                                     \
    "movq	"#a", "L4"\n\t"                      \
    /* L2 = f */                                     \
    "movq	"#f", "L2"\n\t"                      \
    /* h += W_X[i] */                                \
    "addq	("#i")*8("WX"), "#h"\n\t"            \
    /* L2 = f ^ g */                                 \
    "xorq	"#g", "L2"\n\t"                      \

#define RND_1_2_A(a,b,c,d,e,f,g,h,i)                 \
    /* L4 = a */                                     \
    "movq	"#a", "L4"\n\t"                      \
    /* L2 = f */                                     \
    "movq	"#f", "L2"\n\t"                      \

#define RND_1_2_B(a,b,c,d,e,f,g,h,i)                 \
    /* h += W_X[i] */                                \
    "addq	("#i")*8("WX"), "#h"\n\t"            \
    /* L2 = f ^ g */                                 \
    "xorq	"#g", "L2"\n\t"                      \

#define RND_1_3(a,b,c,d,e,f,g,h,i)                   \
    /* L1 = (e >>> 23) ^ e */                        \
    "xorq	"#e", "L1"\n\t"                      \
    /* L2 = (f ^ g) & e */                           \
    "andq	"#e", "L2"\n\t"                      \

#define RND_1_4(a,b,c,d,e,f,g,h,i)                   \
    /* ((e >>> 23) ^ e) >>> 4 */                     \
    "rorq	 $4, "L1"\n\t"                       \
    /* ((f ^ g) & e) ^ g */                          \
    "xorq	"#g", "L2"\n\t"                      \

#define RND_1_5(a,b,c,d,e,f,g,h,i)                   \
    /* (((e >>> 23) ^ e) >>> 4) ^ e */               \
    "xorq	"#e", "L1"\n\t"                      \
    /* h += Ch(e,f,g) */                             \
    "addq	"L2", "#h"\n\t"                      \

#define RND_1_6(a,b,c,d,e,f,g,h,i)                   \
    /* L1 = ((((e >>> 23) ^ e) >>> 4) ^ e) >>> 14 */ \
    "rorq	$14, "L1"\n\t"                       \
    /* L4 = a ^ b */                                 \
    "xorq	"#b", "L4"\n\t"                      \

#define RND_1_7(a,b,c,d,e,f,g,h,i)                   \
    /* h += Sigma1(e) */                             \
    "addq	"L1", "#h"\n\t"                      \
    /* L2 = a */                                     \
    "movq	"#a", "L2"\n\t"                      \

#define RND_1_8(a,b,c,d,e,f,g,h,i)                   \
    /* L3 = (a ^ b) & (b ^ c) */                     \
    "andq	"L4", "L3"\n\t"                      \
    /* L2 = a >>> 5 */                               \
    "rorq	$5, "L2"\n\t"                        \

#define RND_1_9(a,b,c,d,e,f,g,h,i)                   \
    /* L2 = (a >>> 5) ^ a */                         \
    "xorq	"#a", "L2"\n\t"                      \
    /* L3 = ((a ^ b) & (b ^ c) ^ b */                \
    "xorq	"#b", "L3"\n\t"                      \

#define RND_1_10(a,b,c,d,e,f,g,h,i)                  \
    /* L2 = ((a >>> 5) ^ a) >>> 6 */                 \
    "rorq	 $6, "L2"\n\t"                       \
    /* d += h */                                     \
    "addq	"#h", "#d"\n\t"                      \

#define RND_1_11(a,b,c,d,e,f,g,h,i)                  \
    /* L2 = (((a >>> 5) ^ a) >>> 6) ^ a */           \
    "xorq	"#a", "L2"\n\t"                      \
    /* h += Sigma0(a) */                             \
    "addq	"L3", "#h"\n\t"                      \

#define RND_1_12(a,b,c,d,e,f,g,h,i)                  \
    /* L2 = ((((a >>> 5) ^ a) >>> 6) ^ a) >>> 28 */  \
    "rorq	$28, "L2"\n\t"                       \
    /* d (= e next RND) */                           \
    "movq	"#d", "L1"\n\t"                      \
    /* h += Maj(a,b,c) */                            \
    "addq	"L2", "#h"\n\t"                      \


#define MsgSched2(W_0,W_2,W_4,W_6,W_8,W_10,W_12,W_14,a,b,c,d,e,f,g,h,i) \
            RND_0_1(a,b,c,d,e,f,g,h,i)                                  \
    VPALIGNR(W_M15, W_2, W_0, 8)                                        \
    VPALIGNR(W_M7, W_10, W_8, 8)                                        \
            RND_0_2(a,b,c,d,e,f,g,h,i)                                  \
    V_SHIFT_R(XTMP1, W_M15, 1)                                          \
    V_SHIFT_L(XTMP2, W_M15, 63)                                         \
            RND_0_3(a,b,c,d,e,f,g,h,i)                                  \
            RND_0_4(a,b,c,d,e,f,g,h,i)                                  \
    V_SHIFT_R(XTMP3, W_M15, 8)                                          \
    V_SHIFT_L(XTMP4, W_M15, 56)                                         \
            RND_0_5(a,b,c,d,e,f,g,h,i)                                  \
            RND_0_6(a,b,c,d,e,f,g,h,i)                                  \
    V_OR(XTMP1, XTMP2, XTMP1)                                           \
    V_OR(XTMP3, XTMP4, XTMP3)                                           \
            RND_0_7(a,b,c,d,e,f,g,h,i)                                  \
            RND_0_8(a,b,c,d,e,f,g,h,i)                                  \
    V_SHIFT_R(XTMP4, W_M15, 7)                                          \
    V_XOR(XTMP1, XTMP3, XTMP1)                                          \
            RND_0_9(a,b,c,d,e,f,g,h,i)                                  \
            RND_0_10(a,b,c,d,e,f,g,h,i)                                 \
    V_XOR(XTMP1, XTMP4, XTMP1)                                          \
    V_ADD(W_0, W_0, W_M7)                                               \
            RND_0_11(a,b,c,d,e,f,g,h,i)                                 \
            RND_0_12(a,b,c,d,e,f,g,h,i)                                 \
            RND_1_1(h,a,b,c,d,e,f,g,i+1)                                \
    V_ADD(W_0, W_0, XTMP1)                                              \
            RND_1_2(h,a,b,c,d,e,f,g,i+1)                                \
    V_SHIFT_R(XTMP1, W_14, 19)                                          \
    V_SHIFT_L(XTMP2, W_14, 45)                                          \
            RND_1_3(h,a,b,c,d,e,f,g,i+1)                                \
            RND_1_4(h,a,b,c,d,e,f,g,i+1)                                \
    V_SHIFT_R(XTMP3, W_14, 61)                                          \
    V_SHIFT_L(XTMP4, W_14, 3)                                           \
            RND_1_5(h,a,b,c,d,e,f,g,i+1)                                \
            RND_1_6(h,a,b,c,d,e,f,g,i+1)                                \
            RND_1_7(h,a,b,c,d,e,f,g,i+1)                                \
    V_OR(XTMP1, XTMP2, XTMP1)                                           \
    V_OR(XTMP3, XTMP4, XTMP3)                                           \
            RND_1_8(h,a,b,c,d,e,f,g,i+1)                                \
            RND_1_9(h,a,b,c,d,e,f,g,i+1)                                \
    V_XOR(XTMP1, XTMP3, XTMP1)                                          \
    V_SHIFT_R(XTMP4, W_14, 6)                                           \
            RND_1_10(h,a,b,c,d,e,f,g,i+1)                               \
            RND_1_11(h,a,b,c,d,e,f,g,i+1)                               \
    V_XOR(XTMP1, XTMP4, XTMP1)                                          \
            RND_1_12(h,a,b,c,d,e,f,g,i+1)                               \
    V_ADD(W_0, W_0, XTMP1)                                              \

#define RND_ALL_2(a, b, c, d, e, f, g, h, i) \
    RND_0_1 (a, b, c, d, e, f, g, h, i )     \
    RND_0_2 (a, b, c, d, e, f, g, h, i )     \
    RND_0_3 (a, b, c, d, e, f, g, h, i )     \
    RND_0_4 (a, b, c, d, e, f, g, h, i )     \
    RND_0_5 (a, b, c, d, e, f, g, h, i )     \
    RND_0_6 (a, b, c, d, e, f, g, h, i )     \
    RND_0_7 (a, b, c, d, e, f, g, h, i )     \
    RND_0_8 (a, b, c, d, e, f, g, h, i )     \
    RND_0_9 (a, b, c, d, e, f, g, h, i )     \
    RND_0_10(a, b, c, d, e, f, g, h, i )     \
    RND_0_11(a, b, c, d, e, f, g, h, i )     \
    RND_0_12(a, b, c, d, e, f, g, h, i )     \
    RND_1_1 (h, a, b, c, d, e, f, g, i+1)    \
    RND_1_2 (h, a, b, c, d, e, f, g, i+1)    \
    RND_1_3 (h, a, b, c, d, e, f, g, i+1)    \
    RND_1_4 (h, a, b, c, d, e, f, g, i+1)    \
    RND_1_5 (h, a, b, c, d, e, f, g, i+1)    \
    RND_1_6 (h, a, b, c, d, e, f, g, i+1)    \
    RND_1_7 (h, a, b, c, d, e, f, g, i+1)    \
    RND_1_8 (h, a, b, c, d, e, f, g, i+1)    \
    RND_1_9 (h, a, b, c, d, e, f, g, i+1)    \
    RND_1_10(h, a, b, c, d, e, f, g, i+1)    \
    RND_1_11(h, a, b, c, d, e, f, g, i+1)    \
    RND_1_12(h, a, b, c, d, e, f, g, i+1)


#if defined(HAVE_INTEL_RORX)

#define RND_RORX_0_1(a, b, c, d, e, f, g, h, i) \
    /* L1 = e>>>14 */                           \
    "rorxq	$14, "#e", "L1"\n\t"            \
    /* L2 = e>>>18 */                           \
    "rorxq	$18, "#e", "L2"\n\t"            \
    /* Prev RND: h += Maj(a,b,c) */             \
    "addq	"L3", "#a"\n\t"                 \

#define RND_RORX_0_2(a, b, c, d, e, f, g, h, i) \
    /* h += w_k */                              \
    "addq	("#i")*8("WX"), "#h"\n\t"       \
    /* L3 = f */                                \
    "movq	"#f", "L3"\n\t"                 \
    /* L2 = (e>>>14) ^ (e>>>18) */              \
    "xorq	"L1", "L2"\n\t"                 \

#define RND_RORX_0_3(a, b, c, d, e, f, g, h, i) \
    /* L3 = f ^ g */                            \
    "xorq	"#g", "L3"\n\t"                 \
    /* L1 = e>>>41 */                           \
    "rorxq	$41, "#e", "L1"\n\t"            \
    /* L1 = Sigma1(e) */                        \
    "xorq	"L2", "L1"\n\t"                 \

#define RND_RORX_0_4(a, b, c, d, e, f, g, h, i) \
    /* L3 = (f ^ g) & e */                      \
    "andq	"#e", "L3"\n\t"                 \
    /* h += Sigma1(e) */                        \
    "addq	"L1", "#h"\n\t"                 \
    /* L1 = a>>>28 */                           \
    "rorxq	$28, "#a", "L1"\n\t"            \

#define RND_RORX_0_5(a, b, c, d, e, f, g, h, i) \
    /* L2 = a>>>34 */                           \
    "rorxq	$34, "#a", "L2"\n\t"            \
    /* L3 = Ch(e,f,g) */                        \
    "xorq	"#g", "L3"\n\t"                 \
    /* L2 = (a>>>28) ^ (a>>>34) */              \
    "xorq	"L1", "L2"\n\t"                 \

#define RND_RORX_0_6(a, b, c, d, e, f, g, h, i) \
    /* L1 = a>>>39 */                           \
    "rorxq	$39, "#a", "L1"\n\t"            \
    /* h += Ch(e,f,g) */                        \
    "addq	"L3", "#h"\n\t"                 \
    /* L1 = Sigma0(a) */                        \
    "xorq	"L2", "L1"\n\t"                 \

#define RND_RORX_0_7(a, b, c, d, e, f, g, h, i) \
    /* L3 = b */                                \
    "movq	"#b", "L3"\n\t"                 \
    /* d += h + w_k + Sigma1(e) + Ch(e,f,g) */  \
    "addq	"#h", "#d"\n\t"                 \
    /* L3 = a ^ b */                            \
    "xorq	"#a", "L3"\n\t"                 \

#define RND_RORX_0_8(a, b, c, d, e, f, g, h, i) \
    /* L4 = (a ^ b) & (b ^ c) */                \
    "andq	"L3", "L4"\n\t"                 \
    /* h += Sigma0(a) */                        \
    "addq	"L1", "#h"\n\t"                 \
    /* L4 = Maj(a,b,c) */                       \
    "xorq	"#b", "L4"\n\t"                 \

#define RND_RORX_1_1(a, b, c, d, e, f, g, h, i) \
    /* L1 = e>>>14 */                           \
    "rorxq	$14, "#e", "L1"\n\t"            \
    /* L2 = e>>>18 */                           \
    "rorxq	$18, "#e", "L2"\n\t"            \
    /* Prev RND: h += Maj(a,b,c) */             \
    "addq	"L4", "#a"\n\t"                 \

#define RND_RORX_1_2(a, b, c, d, e, f, g, h, i) \
    /* h += w_k */                              \
    "addq	("#i")*8("WX"), "#h"\n\t"       \
    /* L4 = f */                                \
    "movq	"#f", "L4"\n\t"                 \
    /* L2 = (e>>>14) ^ (e>>>18) */              \
    "xorq	"L1", "L2"\n\t"                 \

#define RND_RORX_1_3(a, b, c, d, e, f, g, h, i) \
    /* L4 = f ^ g */                            \
    "xorq	"#g", "L4"\n\t"                 \
    /* L1 = e>>>41 */                           \
    "rorxq	$41, "#e", "L1"\n\t"            \
    /* L1 = Sigma1(e) */                        \
    "xorq	"L2", "L1"\n\t"                 \

#define RND_RORX_1_4(a, b, c, d, e, f, g, h, i) \
    /* L4 = (f ^ g) & e */                      \
    "andq	"#e", "L4"\n\t"                 \
    /* h += Sigma1(e) */                        \
    "addq	"L1", "#h"\n\t"                 \
    /* L1 = a>>>28 */                           \
    "rorxq	$28, "#a", "L1"\n\t"            \

#define RND_RORX_1_5(a, b, c, d, e, f, g, h, i) \
    /* L2 = a>>>34 */                           \
    "rorxq	$34, "#a", "L2"\n\t"            \
    /* L4 = Ch(e,f,g) */                        \
    "xorq	"#g", "L4"\n\t"                 \
    /* L2 = (a>>>28) ^ (a>>>34) */              \
    "xorq	"L1", "L2"\n\t"                 \

#define RND_RORX_1_6(a, b, c, d, e, f, g, h, i) \
    /* L1 = a>>>39 */                           \
    "rorxq	$39, "#a", "L1"\n\t"            \
    /* h += Ch(e,f,g) */                        \
    "addq	"L4", "#h"\n\t"                 \
    /* L1 = Sigma0(a) */                        \
    "xorq	"L2", "L1"\n\t"                 \

#define RND_RORX_1_7(a, b, c, d, e, f, g, h, i) \
    /* L4 = b */                                \
    "movq	"#b", "L4"\n\t"                 \
    /* d += h + w_k + Sigma1(e) + Ch(e,f,g) */  \
    "addq	"#h", "#d"\n\t"                 \
    /* L4 = a ^ b */                            \
    "xorq	"#a", "L4"\n\t"                 \

#define RND_RORX_1_8(a, b, c, d, e, f, g, h, i) \
    /* L2 = (a ^ b) & (b ^ c) */                \
    "andq	"L4", "L3"\n\t"                 \
    /* h += Sigma0(a) */                        \
    "addq	"L1", "#h"\n\t"                 \
    /* L3 = Maj(a,b,c) */                       \
    "xorq	"#b", "L3"\n\t"                 \

#define RND_RORX_ALL_2(a, b, c, d, e, f, g, h, i) \
    RND_RORX_0_1(a, b, c, d, e, f, g, h, i+0)     \
    RND_RORX_0_2(a, b, c, d, e, f, g, h, i+0)     \
    RND_RORX_0_3(a, b, c, d, e, f, g, h, i+0)     \
    RND_RORX_0_4(a, b, c, d, e, f, g, h, i+0)     \
    RND_RORX_0_5(a, b, c, d, e, f, g, h, i+0)     \
    RND_RORX_0_6(a, b, c, d, e, f, g, h, i+0)     \
    RND_RORX_0_7(a, b, c, d, e, f, g, h, i+0)     \
    RND_RORX_0_8(a, b, c, d, e, f, g, h, i+0)     \
    RND_RORX_1_1(h, a, b, c, d, e, f, g, i+1)     \
    RND_RORX_1_2(h, a, b, c, d, e, f, g, i+1)     \
    RND_RORX_1_3(h, a, b, c, d, e, f, g, i+1)     \
    RND_RORX_1_4(h, a, b, c, d, e, f, g, i+1)     \
    RND_RORX_1_5(h, a, b, c, d, e, f, g, i+1)     \
    RND_RORX_1_6(h, a, b, c, d, e, f, g, i+1)     \
    RND_RORX_1_7(h, a, b, c, d, e, f, g, i+1)     \
    RND_RORX_1_8(h, a, b, c, d, e, f, g, i+1)     \

#define RND_RORX_ALL_4(a, b, c, d, e, f, g, h, i) \
    RND_RORX_ALL_2(a, b, c, d, e, f, g, h, i+0)   \
    RND_RORX_ALL_2(g, h, a, b, c, d, e, f, i+2)

#define MsgSched_RORX(W_0,W_2,W_4,W_6,W_8,W_10,W_12,W_14,a,b,c,d,e,f,g,h,i) \
            RND_RORX_0_1(a,b,c,d,e,f,g,h,i)                                 \
    VPALIGNR(W_M15, W_2, W_0, 8)                                            \
    VPALIGNR(W_M7, W_10, W_8, 8)                                            \
            RND_RORX_0_2(a,b,c,d,e,f,g,h,i)                                 \
    V_SHIFT_R(XTMP1, W_M15, 1)                                              \
    V_SHIFT_L(XTMP2, W_M15, 63)                                             \
            RND_RORX_0_3(a,b,c,d,e,f,g,h,i)                                 \
    V_SHIFT_R(XTMP3, W_M15, 8)                                              \
    V_SHIFT_L(XTMP4, W_M15, 56)                                             \
            RND_RORX_0_4(a,b,c,d,e,f,g,h,i)                                 \
    V_OR(XTMP1, XTMP2, XTMP1)                                               \
    V_OR(XTMP3, XTMP4, XTMP3)                                               \
            RND_RORX_0_5(a,b,c,d,e,f,g,h,i)                                 \
    V_SHIFT_R(XTMP4, W_M15, 7)                                              \
    V_XOR(XTMP1, XTMP3, XTMP1)                                              \
            RND_RORX_0_6(a,b,c,d,e,f,g,h,i)                                 \
    V_XOR(XTMP1, XTMP4, XTMP1)                                              \
    V_ADD(W_0, W_0, W_M7)                                                   \
            RND_RORX_0_7(a,b,c,d,e,f,g,h,i)                                 \
            RND_RORX_0_8(a,b,c,d,e,f,g,h,i)                                 \
    V_ADD(W_0, W_0, XTMP1)                                                  \
            RND_RORX_1_1(h,a,b,c,d,e,f,g,i+1)                               \
    V_SHIFT_R(XTMP1, W_14, 19)                                              \
    V_SHIFT_L(XTMP2, W_14, 45)                                              \
            RND_RORX_1_2(h,a,b,c,d,e,f,g,i+1)                               \
    V_SHIFT_R(XTMP3, W_14, 61)                                              \
    V_SHIFT_L(XTMP4, W_14, 3)                                               \
            RND_RORX_1_3(h,a,b,c,d,e,f,g,i+1)                               \
    V_OR(XTMP1, XTMP2, XTMP1)                                               \
    V_OR(XTMP3, XTMP4, XTMP3)                                               \
            RND_RORX_1_4(h,a,b,c,d,e,f,g,i+1)                               \
            RND_RORX_1_5(h,a,b,c,d,e,f,g,i+1)                               \
    V_XOR(XTMP1, XTMP3, XTMP1)                                              \
    V_SHIFT_R(XTMP4, W_14, 6)                                               \
            RND_RORX_1_6(h,a,b,c,d,e,f,g,i+1)                               \
            RND_RORX_1_7(h,a,b,c,d,e,f,g,i+1)                               \
    V_XOR(XTMP1, XTMP4, XTMP1)                                              \
            RND_RORX_1_8(h,a,b,c,d,e,f,g,i+1)                               \
    V_ADD(W_0, W_0, XTMP1)                                                  \

#endif

#define _INIT_MASK(mask) \
    "vmovdqu %[mask], %%"#mask"\n\t"
#define INIT_MASK(mask) \
       _INIT_MASK(mask)

#define _LOAD_W_2(i1, i2, xmm1, xmm2, mask, reg)     \
    "vmovdqu	"#i1"*16(%%"#reg"), %%"#xmm1"\n\t"   \
    "vmovdqu	"#i2"*16(%%"#reg"), %%"#xmm2"\n\t"   \
    "vpshufb	%%"#mask", %%"#xmm1", %%"#xmm1"\n\t" \
    "vpshufb	%%"#mask", %%"#xmm2", %%"#xmm2"\n\t"
#define LOAD_W_2(i1, i2, xmm1, xmm2, mask, reg) \
       _LOAD_W_2(i1, i2, xmm1, xmm2, mask, reg)

#define LOAD_W(mask, reg)                           \
    /* X0..3(xmm4..7), W[0..15] = buffer[0.15];  */ \
    LOAD_W_2(0, 1, W_0 , W_2 , mask, reg)           \
    LOAD_W_2(2, 3, W_4 , W_6 , mask, reg)           \
    LOAD_W_2(4, 5, W_8 , W_10, mask, reg)           \
    LOAD_W_2(6, 7, W_12, W_14, mask, reg)

#define _SET_W_X_2(xmm0, xmm1, reg, i)                    \
    "vpaddq	"#i"+ 0(%%"#reg"), %%"#xmm0", %%xmm8\n\t" \
    "vpaddq	"#i"+16(%%"#reg"), %%"#xmm1", %%xmm9\n\t" \
    "vmovdqu	%%xmm8, "#i"+ 0("WX")\n\t"                \
    "vmovdqu	%%xmm9, "#i"+16("WX")\n\t"                \

#define SET_W_X_2(xmm0, xmm1, reg, i) \
       _SET_W_X_2(xmm0, xmm1, reg, i)

#define SET_W_X(reg)                \
    SET_W_X_2(W_0 , W_2 , reg,  0)  \
    SET_W_X_2(W_4 , W_6 , reg, 32)  \
    SET_W_X_2(W_8 , W_10, reg, 64)  \
    SET_W_X_2(W_12, W_14, reg, 96)

#define LOAD_DIGEST()                     \
    "movq	  (%[sha512]), %%r8 \n\t" \
    "movq	 8(%[sha512]), %%r9 \n\t" \
    "movq	16(%[sha512]), %%r10\n\t" \
    "movq	24(%[sha512]), %%r11\n\t" \
    "movq	32(%[sha512]), %%r12\n\t" \
    "movq	40(%[sha512]), %%r13\n\t" \
    "movq	48(%[sha512]), %%r14\n\t" \
    "movq	56(%[sha512]), %%r15\n\t"

#define STORE_ADD_DIGEST()                \
    "addq	 %%r8,   (%[sha512])\n\t" \
    "addq	 %%r9,  8(%[sha512])\n\t" \
    "addq	%%r10, 16(%[sha512])\n\t" \
    "addq	%%r11, 24(%[sha512])\n\t" \
    "addq	%%r12, 32(%[sha512])\n\t" \
    "addq	%%r13, 40(%[sha512])\n\t" \
    "addq	%%r14, 48(%[sha512])\n\t" \
    "addq	%%r15, 56(%[sha512])\n\t"

#define ADD_DIGEST()                      \
    "addq	  (%[sha512]), %%r8 \n\t" \
    "addq	 8(%[sha512]), %%r9 \n\t" \
    "addq	16(%[sha512]), %%r10\n\t" \
    "addq	24(%[sha512]), %%r11\n\t" \
    "addq	32(%[sha512]), %%r12\n\t" \
    "addq	40(%[sha512]), %%r13\n\t" \
    "addq	48(%[sha512]), %%r14\n\t" \
    "addq	56(%[sha512]), %%r15\n\t"

#define STORE_DIGEST()                    \
    "movq	 %%r8,   (%[sha512])\n\t" \
    "movq	 %%r9,  8(%[sha512])\n\t" \
    "movq	%%r10, 16(%[sha512])\n\t" \
    "movq	%%r11, 24(%[sha512])\n\t" \
    "movq	%%r12, 32(%[sha512])\n\t" \
    "movq	%%r13, 40(%[sha512])\n\t" \
    "movq	%%r14, 48(%[sha512])\n\t" \
    "movq	%%r15, 56(%[sha512])\n\t"

#endif /* HAVE_INTEL_AVX1 */


/***  Transform Body ***/
#if defined(HAVE_INTEL_AVX1)
static int Transform_Sha512_AVX1(wc_Sha512* sha512)
{
    __asm__ __volatile__ (

        /* 16 Ws plus loop counter. */
        "subq	$136, %%rsp\n\t"
        "leaq	64(%[sha512]), %%rax\n\t"

    INIT_MASK(MASK)
    LOAD_DIGEST()

    LOAD_W(MASK, rax)

        "movl	$4, 16*8("WX")\n\t"
        "leaq	%[K512], %%rsi\n\t"
        /* b */
        "movq	%%r9, "L4"\n\t"
        /* e */
        "movq	%%r12, "L1"\n\t"
        /* b ^ c */
        "xorq	%%r10, "L4"\n\t"

        "# Start of 16 rounds\n"
        "1:\n\t"

    SET_W_X(rsi)

        "addq	$128, %%rsi\n\t"

    MsgSched2(W_0,W_2,W_4,W_6,W_8,W_10,W_12,W_14,RA,RB,RC,RD,RE,RF,RG,RH, 0)
    MsgSched2(W_2,W_4,W_6,W_8,W_10,W_12,W_14,W_0,RG,RH,RA,RB,RC,RD,RE,RF, 2)
    MsgSched2(W_4,W_6,W_8,W_10,W_12,W_14,W_0,W_2,RE,RF,RG,RH,RA,RB,RC,RD, 4)
    MsgSched2(W_6,W_8,W_10,W_12,W_14,W_0,W_2,W_4,RC,RD,RE,RF,RG,RH,RA,RB, 6)
    MsgSched2(W_8,W_10,W_12,W_14,W_0,W_2,W_4,W_6,RA,RB,RC,RD,RE,RF,RG,RH, 8)
    MsgSched2(W_10,W_12,W_14,W_0,W_2,W_4,W_6,W_8,RG,RH,RA,RB,RC,RD,RE,RF,10)
    MsgSched2(W_12,W_14,W_0,W_2,W_4,W_6,W_8,W_10,RE,RF,RG,RH,RA,RB,RC,RD,12)
    MsgSched2(W_14,W_0,W_2,W_4,W_6,W_8,W_10,W_12,RC,RD,RE,RF,RG,RH,RA,RB,14)

        "subl	$1, 16*8("WX")\n\t"
        "jne	1b\n\t"

    SET_W_X(rsi)

    RND_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH, 0)
    RND_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF, 2)
    RND_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD, 4)
    RND_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB, 6)

    RND_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH, 8)
    RND_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF,10)
    RND_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD,12)
    RND_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB,14)

    STORE_ADD_DIGEST()

        "addq	$136, %%rsp\n\t"

        :
        : [mask]   "m" (mBYTE_FLIP_MASK),
          [sha512] "r" (sha512),
          [K512]   "m" (K512)
        : WORK_REGS, STATE_REGS, XMM_REGS, "memory", "rsi"
    );

    return 0;
}

static int Transform_Sha512_AVX1_Len(wc_Sha512* sha512, word32 len)
{
    __asm__ __volatile__ (

        "movq	224(%[sha512]), %%rsi\n\t"
        "leaq	%[K512], %%rdx\n\t"

    INIT_MASK(MASK)
    LOAD_DIGEST()

        "# Start of processing a block\n"
        "2:\n\t"

        /* 16 Ws plus loop counter and K512. len goes into -4(%rsp).
         * Debug needs more stack space. */
        "subq	$256, %%rsp\n\t"

    LOAD_W(MASK, rsi)

        "movl	$4, 16*8("WX")\n\t"
        /* b */
        "movq	%%r9, "L4"\n\t"
        /* e */
        "movq	%%r12, "L1"\n\t"
        /* b ^ c */
        "xorq	%%r10, "L4"\n\t"

    SET_W_X(rdx)

        "# Start of 16 rounds\n"
        "1:\n\t"

        "addq	$128, %%rdx\n\t"
        "movq	%%rdx, 17*8(%%rsp)\n\t"

    MsgSched2(W_0,W_2,W_4,W_6,W_8,W_10,W_12,W_14,RA,RB,RC,RD,RE,RF,RG,RH, 0)
    MsgSched2(W_2,W_4,W_6,W_8,W_10,W_12,W_14,W_0,RG,RH,RA,RB,RC,RD,RE,RF, 2)
    MsgSched2(W_4,W_6,W_8,W_10,W_12,W_14,W_0,W_2,RE,RF,RG,RH,RA,RB,RC,RD, 4)
    MsgSched2(W_6,W_8,W_10,W_12,W_14,W_0,W_2,W_4,RC,RD,RE,RF,RG,RH,RA,RB, 6)
    MsgSched2(W_8,W_10,W_12,W_14,W_0,W_2,W_4,W_6,RA,RB,RC,RD,RE,RF,RG,RH, 8)
    MsgSched2(W_10,W_12,W_14,W_0,W_2,W_4,W_6,W_8,RG,RH,RA,RB,RC,RD,RE,RF,10)
    MsgSched2(W_12,W_14,W_0,W_2,W_4,W_6,W_8,W_10,RE,RF,RG,RH,RA,RB,RC,RD,12)
    MsgSched2(W_14,W_0,W_2,W_4,W_6,W_8,W_10,W_12,RC,RD,RE,RF,RG,RH,RA,RB,14)

        "movq	17*8(%%rsp), %%rdx\n\t"

    SET_W_X(rdx)

        "subl	$1, 16*8("WX")\n\t"
        "jne	1b\n\t"

    RND_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH, 0)
    RND_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF, 2)
    RND_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD, 4)
    RND_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB, 6)

    RND_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH, 8)
    RND_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF,10)
    RND_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD,12)
    RND_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB,14)

    ADD_DIGEST()

        "addq	$256, %%rsp\n\t"
        "leaq	%[K512], %%rdx\n\t"
        "addq	$128, %%rsi\n\t"
        "subl	$128, %[len]\n\t"

    STORE_DIGEST()

        "jnz	2b\n\t"

        :
        : [mask]   "m" (mBYTE_FLIP_MASK),
          [len]    "m" (len),
          [sha512] "r" (sha512),
          [K512]   "m" (K512)
        : WORK_REGS, STATE_REGS, XMM_REGS, "memory", "rsi"
    );

    return 0;
}
#endif /* HAVE_INTEL_AVX1 */

#if defined(HAVE_INTEL_AVX2) && defined(HAVE_INTEL_RORX)
static int Transform_Sha512_AVX1_RORX(wc_Sha512* sha512)
{
    __asm__ __volatile__ (

        /* 16 Ws plus loop counter and K512. */
        "subq	$144, %%rsp\n\t"
        "leaq	64(%[sha512]), %%rax\n\t"

    INIT_MASK(MASK)
    LOAD_DIGEST()

    LOAD_W(MASK, rax)

        "movl	$4, 16*8("WX")\n\t"
        "leaq	%[K512], %%rsi\n\t"
        /* L4 = b */
        "movq	%%r9, "L4"\n\t"
        /* L3 = 0 (add to prev h) */
        "xorq	"L3", "L3"\n\t"
        /* L4 = b ^ c */
        "xorq	%%r10, "L4"\n\t"

    SET_W_X(rsi)

        "# Start of 16 rounds\n"
        "1:\n\t"

        "addq	$128, %%rsi\n\t"

    MsgSched_RORX(W_0,W_2,W_4,W_6,W_8,W_10,W_12,W_14,RA,RB,RC,RD,RE,RF,RG,RH, 0)
    MsgSched_RORX(W_2,W_4,W_6,W_8,W_10,W_12,W_14,W_0,RG,RH,RA,RB,RC,RD,RE,RF, 2)
    MsgSched_RORX(W_4,W_6,W_8,W_10,W_12,W_14,W_0,W_2,RE,RF,RG,RH,RA,RB,RC,RD, 4)
    MsgSched_RORX(W_6,W_8,W_10,W_12,W_14,W_0,W_2,W_4,RC,RD,RE,RF,RG,RH,RA,RB, 6)
    MsgSched_RORX(W_8,W_10,W_12,W_14,W_0,W_2,W_4,W_6,RA,RB,RC,RD,RE,RF,RG,RH, 8)
    MsgSched_RORX(W_10,W_12,W_14,W_0,W_2,W_4,W_6,W_8,RG,RH,RA,RB,RC,RD,RE,RF,10)
    MsgSched_RORX(W_12,W_14,W_0,W_2,W_4,W_6,W_8,W_10,RE,RF,RG,RH,RA,RB,RC,RD,12)
    MsgSched_RORX(W_14,W_0,W_2,W_4,W_6,W_8,W_10,W_12,RC,RD,RE,RF,RG,RH,RA,RB,14)

    SET_W_X(rsi)

        "subl	$1, 16*8("WX")\n\t"
        "jne	1b\n\t"

    RND_RORX_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH, 0)
    RND_RORX_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF, 2)
    RND_RORX_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD, 4)
    RND_RORX_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB, 6)

    RND_RORX_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH, 8)
    RND_RORX_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF,10)
    RND_RORX_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD,12)
    RND_RORX_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB,14)

        /* Prev RND: h += Maj(a,b,c) */
        "addq	"L3", %%r8\n\t"
        "addq	$144, %%rsp\n\t"

    STORE_ADD_DIGEST()

        :
        : [mask]   "m" (mBYTE_FLIP_MASK),
          [sha512] "r" (sha512),
          [K512]   "m" (K512)
        : WORK_REGS, STATE_REGS, XMM_REGS, "memory", "rsi"
    );

    return 0;
}

static int Transform_Sha512_AVX1_RORX_Len(wc_Sha512* sha512, word32 len)
{
    __asm__ __volatile__ (

        "movq	224(%[sha512]), %%rsi\n\t"
        "leaq	%[K512], %%rcx\n\t"

    INIT_MASK(MASK)
    LOAD_DIGEST()

        "# Start of processing a block\n"
        "2:\n\t"

        /* 16 Ws plus loop counter and K512. len goes into -4(%rsp).
         * Debug needs more stack space. */
        "subq	$256, %%rsp\n\t"

    LOAD_W(MASK, rsi)

        "movl	$4, 16*8("WX")\n\t"
        /* L4 = b */
        "movq	%%r9, "L4"\n\t"
        /* L3 = 0 (add to prev h) */
        "xorq	"L3", "L3"\n\t"
        /* L4 = b ^ c */
        "xorq	%%r10, "L4"\n\t"

    SET_W_X(rcx)

        "# Start of 16 rounds\n"
        "1:\n\t"

        "addq	$128, %%rcx\n\t"
        "movq	%%rcx, 17*8(%%rsp)\n\t"

    MsgSched_RORX(W_0,W_2,W_4,W_6,W_8,W_10,W_12,W_14,RA,RB,RC,RD,RE,RF,RG,RH, 0)
    MsgSched_RORX(W_2,W_4,W_6,W_8,W_10,W_12,W_14,W_0,RG,RH,RA,RB,RC,RD,RE,RF, 2)
    MsgSched_RORX(W_4,W_6,W_8,W_10,W_12,W_14,W_0,W_2,RE,RF,RG,RH,RA,RB,RC,RD, 4)
    MsgSched_RORX(W_6,W_8,W_10,W_12,W_14,W_0,W_2,W_4,RC,RD,RE,RF,RG,RH,RA,RB, 6)
    MsgSched_RORX(W_8,W_10,W_12,W_14,W_0,W_2,W_4,W_6,RA,RB,RC,RD,RE,RF,RG,RH, 8)
    MsgSched_RORX(W_10,W_12,W_14,W_0,W_2,W_4,W_6,W_8,RG,RH,RA,RB,RC,RD,RE,RF,10)
    MsgSched_RORX(W_12,W_14,W_0,W_2,W_4,W_6,W_8,W_10,RE,RF,RG,RH,RA,RB,RC,RD,12)
    MsgSched_RORX(W_14,W_0,W_2,W_4,W_6,W_8,W_10,W_12,RC,RD,RE,RF,RG,RH,RA,RB,14)

        "movq	17*8(%%rsp), %%rcx\n\t"

    SET_W_X(rcx)

        "subl	$1, 16*8("WX")\n\t"
        "jne	1b\n\t"

    SET_W_X(rcx)

    RND_RORX_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH, 0)
    RND_RORX_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF, 2)
    RND_RORX_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD, 4)
    RND_RORX_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB, 6)

    RND_RORX_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH, 8)
    RND_RORX_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF,10)
    RND_RORX_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD,12)
    RND_RORX_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB,14)

        /* Prev RND: h += Maj(a,b,c) */
        "addq	"L3", %%r8\n\t"
        "addq	$256, %%rsp\n\t"

    ADD_DIGEST()

        "leaq	%[K512], %%rcx\n\t"
        "addq	$128, %%rsi\n\t"
        "subl	$128, %[len]\n\t"

    STORE_DIGEST()

        "jnz	2b\n\t"

        :
        : [mask]   "m" (mBYTE_FLIP_MASK),
          [len]    "m" (len),
          [sha512] "r" (sha512),
          [K512]   "m" (K512)
        : WORK_REGS, STATE_REGS, XMM_REGS, "memory", "rsi"
    );

    return 0;
}
#endif /* HAVE_INTEL_AVX2 && HAVE_INTEL_RORX */

#if defined(HAVE_INTEL_AVX2)
static const unsigned long mBYTE_FLIP_MASK_Y[] =
   { 0x0001020304050607, 0x08090a0b0c0d0e0f,
     0x0001020304050607, 0x08090a0b0c0d0e0f };

#define W_Y_0       ymm0
#define W_Y_4       ymm1
#define W_Y_8       ymm2
#define W_Y_12      ymm3

#define X0       xmm0
#define X1       xmm1
#define X2       xmm2
#define X3       xmm3
#define X4       xmm4
#define X5       xmm5
#define X6       xmm6
#define X7       xmm7
#define X8       xmm8
#define X9       xmm9
#define Y0       ymm0
#define Y1       ymm1
#define Y2       ymm2
#define Y3       ymm3
#define Y4       ymm4
#define Y5       ymm5
#define Y6       ymm6
#define Y7       ymm7

#define W_Y_M15     ymm12
#define W_Y_M7      ymm13
#define W_Y_M2      ymm14
#define MASK_Y      ymm15

#define YTMP1       ymm8
#define YTMP2       ymm9
#define YTMP3       ymm10
#define YTMP4       ymm11

#define YMM_REGS \
    "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",       \
    "xmm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15"

#define _VPERM2I128(dest, src1, src2, sel)                     \
    "vperm2I128	$"#sel", %%"#src2", %%"#src1", %%"#dest"\n\t"
#define VPERM2I128(dest, src1, src2, sel) \
       _VPERM2I128(dest, src1, src2, sel)

#define _VPERMQ(dest, src, sel)                                \
    "vpermq	$"#sel", %%"#src", %%"#dest"\n\t"
#define VPERMQ(dest, src, sel) \
       _VPERMQ(dest, src, sel)

#define _VPBLENDD(dest, src1, src2, sel)                       \
    "vpblendd	$"#sel", %%"#src2", %%"#src1", %%"#dest"\n\t"
#define VPBLENDD(dest, src1, src2, sel) \
       _VPBLENDD(dest, src1, src2, sel)

#define _V_ADD_I(dest, src1, addr, i)                          \
    "vpaddq	 "#i"*8(%%"#addr"), %%"#src1", %%"#dest"\n\t"
#define V_ADD_I(dest, src1, addr, i) \
       _V_ADD_I(dest, src1, addr, i)

#define _VMOVDQU_I(addr, i, src)                               \
    "vmovdqu	 %%"#src", "#i"*8(%%"#addr")\n\t"
#define VMOVDQU_I(addr, i, src) \
       _VMOVDQU_I(addr, i, src)

#define MsgSched4_AVX2(W_Y_0,W_Y_4,W_Y_8,W_Y_12,a,b,c,d,e,f,g,h,i) \
            RND_0_1(a,b,c,d,e,f,g,h,i)                             \
    /* W[-13]..W[-15], W[-12] */                                   \
    VPBLENDD(W_Y_M15, W_Y_0, W_Y_4, 0x03)                          \
    /* W[-5]..W[-7], W[-4] */                                      \
    VPBLENDD(W_Y_M7, W_Y_8, W_Y_12, 0x03)                          \
            RND_0_2(a,b,c,d,e,f,g,h,i)                             \
            RND_0_3(a,b,c,d,e,f,g,h,i)                             \
    /* W_Y_M15 = W[-12]..W[-15] */                                 \
    VPERMQ(W_Y_M15, W_Y_M15, 0x39)                                 \
            RND_0_4(a,b,c,d,e,f,g,h,i)                             \
    /* W_Y_M7 = W[-4]..W[-7] */                                    \
    VPERMQ(W_Y_M7, W_Y_M7, 0x39)                                   \
            RND_0_5(a,b,c,d,e,f,g,h,i)                             \
            RND_0_6(a,b,c,d,e,f,g,h,i)                             \
    /* W[-15] >>  1 */                                             \
    V_SHIFT_R(YTMP1, W_Y_M15, 1)                                   \
            RND_0_7(a,b,c,d,e,f,g,h,i)                             \
    /* W[-15] << 63 */                                             \
    V_SHIFT_L(YTMP2, W_Y_M15, 63)                                  \
            RND_0_8(a,b,c,d,e,f,g,h,i)                             \
    /* W[-15] >>  8 */                                             \
    V_SHIFT_R(YTMP3, W_Y_M15, 8)                                   \
            RND_0_9(a,b,c,d,e,f,g,h,i)                             \
    /* W[-15] << 56 */                                             \
    V_SHIFT_L(YTMP4, W_Y_M15, 56)                                  \
            RND_0_10(a,b,c,d,e,f,g,h,i)                            \
    /* W[-15] >>> 1 */                                             \
    V_OR(YTMP1, YTMP2, YTMP1)                                      \
            RND_0_11(a,b,c,d,e,f,g,h,i)                            \
    /* W[-15] >>> 8 */                                             \
    V_OR(YTMP3, YTMP4, YTMP3)                                      \
            RND_0_12(a,b,c,d,e,f,g,h,i)                            \
            RND_1_1(h,a,b,c,d,e,f,g,i+1)                           \
    /* W[-15] >> 7 */                                              \
    V_SHIFT_R(YTMP4, W_Y_M15, 7)                                   \
            RND_1_2_A(h,a,b,c,d,e,f,g,i+1)                         \
    /* (W[-15] >>> 1) ^ (W[-15] >>> 8) */                          \
    V_XOR(YTMP1, YTMP3, YTMP1)                                     \
            RND_1_2_B(h,a,b,c,d,e,f,g,i+1)                         \
    /* (W[-15] >>> 1) ^ (W[-15] >>> 8) ^ (W[-15] >> 7) */          \
    V_XOR(YTMP1, YTMP4, YTMP1)                                     \
            RND_1_3(h,a,b,c,d,e,f,g,i+1)                           \
    /* W[0] = W[-16] + W[-7] */                                    \
    V_ADD(W_Y_0, W_Y_0, W_Y_M7)                                    \
            RND_1_4(h,a,b,c,d,e,f,g,i+1)                           \
    /* W[0] = W[-16] + W[-7] + s0(W[-15]) */                       \
    V_ADD(W_Y_0, W_Y_0, YTMP1)                                     \
            RND_1_5(h,a,b,c,d,e,f,g,i+1)                           \
    /* 0, 0, W[-1], W[-2] */                                       \
    VPERM2I128(W_Y_M2, W_Y_12, W_Y_12, 0x81)                       \
            RND_1_6(h,a,b,c,d,e,f,g,i+1)                           \
            RND_1_7(h,a,b,c,d,e,f,g,i+1)                           \
            RND_1_8(h,a,b,c,d,e,f,g,i+1)                           \
    /* W[-2] >> 19 */                                              \
    V_SHIFT_R(YTMP1, W_Y_M2, 19)                                   \
            RND_1_9(h,a,b,c,d,e,f,g,i+1)                           \
    /* W[-2] << 45 */                                              \
    V_SHIFT_L(YTMP2, W_Y_M2, 45)                                   \
            RND_1_10(h,a,b,c,d,e,f,g,i+1)                          \
    /* W[-2] >> 61 */                                              \
    V_SHIFT_R(YTMP3, W_Y_M2, 61)                                   \
            RND_1_11(h,a,b,c,d,e,f,g,i+1)                          \
    /* W[-2] <<  3 */                                              \
    V_SHIFT_L(YTMP4, W_Y_M2, 3)                                    \
            RND_1_12(h,a,b,c,d,e,f,g,i+1)                          \
            RND_0_1(g,h,a,b,c,d,e,f,i+2)                           \
    /* W[-2] >>> 19 */                                             \
    V_OR(YTMP1, YTMP2, YTMP1)                                      \
            RND_0_2(g,h,a,b,c,d,e,f,i+2)                           \
    /* W[-2] >>> 61 */                                             \
    V_OR(YTMP3, YTMP4, YTMP3)                                      \
            RND_0_3(g,h,a,b,c,d,e,f,i+2)                           \
    /* (W[-2] >>> 19) ^ (W[-2] >>> 61) */                          \
    V_XOR(YTMP1, YTMP3, YTMP1)                                     \
            RND_0_4(g,h,a,b,c,d,e,f,i+2)                           \
    /* W[-2] >>  6 */                                              \
    V_SHIFT_R(YTMP4, W_Y_M2, 6)                                    \
            RND_0_5(g,h,a,b,c,d,e,f,i+2)                           \
    /* (W[-2] >>> 19) ^ (W[-2] >>> 61) ^ (W[-2] >> 6) */           \
    V_XOR(YTMP1, YTMP4, YTMP1)                                     \
            RND_0_6(g,h,a,b,c,d,e,f,i+2)                           \
    /* W[0] = W[-16] + W[-7] + s0(W[-15]) + s1(W[-2]) */           \
    V_ADD(W_Y_0, W_Y_0, YTMP1)                                     \
            RND_0_7(g,h,a,b,c,d,e,f,i+2)                           \
            RND_0_8(g,h,a,b,c,d,e,f,i+2)                           \
    /* W[1], W[0], 0, 0 */                                         \
    VPERM2I128(W_Y_M2, W_Y_0, W_Y_0, 0x08)                         \
            RND_0_9(g,h,a,b,c,d,e,f,i+2)                           \
            RND_0_10(g,h,a,b,c,d,e,f,i+2)                          \
    /* W[-2] >> 19 */                                              \
    V_SHIFT_R(YTMP1, W_Y_M2, 19)                                   \
            RND_0_11(g,h,a,b,c,d,e,f,i+2)                          \
    /* W[-2] << 45 */                                              \
    V_SHIFT_L(YTMP2, W_Y_M2, 45)                                   \
            RND_0_12(g,h,a,b,c,d,e,f,i+2)                          \
            RND_1_1(f,g,h,a,b,c,d,e,i+3)                           \
    /* W[-2] >> 61 */                                              \
    V_SHIFT_R(YTMP3, W_Y_M2, 61)                                   \
            RND_1_2(f,g,h,a,b,c,d,e,i+3)                           \
    /* W[-2] <<  3 */                                              \
    V_SHIFT_L(YTMP4, W_Y_M2, 3)                                    \
            RND_1_3(f,g,h,a,b,c,d,e,i+3)                           \
    /* W[-2] >>> 19 */                                             \
    V_OR(YTMP1, YTMP2, YTMP1)                                      \
            RND_1_4(f,g,h,a,b,c,d,e,i+3)                           \
    /* W[-2] >>> 61 */                                             \
    V_OR(YTMP3, YTMP4, YTMP3)                                      \
            RND_1_5(f,g,h,a,b,c,d,e,i+3)                           \
    /* (W[-2] >>> 19) ^ (W[-2] >>> 61) */                          \
    V_XOR(YTMP1, YTMP3, YTMP1)                                     \
            RND_1_6(f,g,h,a,b,c,d,e,i+3)                           \
    /* W[-2] >>  6 */                                              \
    V_SHIFT_R(YTMP4, W_Y_M2, 6)                                    \
            RND_1_7(f,g,h,a,b,c,d,e,i+3)                           \
    /* (W[-2] >>> 19) ^ (W[-2] >>> 61) ^ (W[-2] >> 6) */           \
    V_XOR(YTMP1, YTMP4, YTMP1)                                     \
            RND_1_8(f,g,h,a,b,c,d,e,i+3)                           \
    /* W[0] = W[-16] + W[-7] + s0(W[-15]) + s1(W[-2]) */           \
    V_ADD(W_Y_0, W_Y_0, YTMP1)                                     \
            RND_1_9(f,g,h,a,b,c,d,e,i+3)                           \
            RND_1_10(f,g,h,a,b,c,d,e,i+3)                          \
            RND_1_11(f,g,h,a,b,c,d,e,i+3)                          \
            RND_1_12(f,g,h,a,b,c,d,e,i+3)                          \

#define MsgSched2_AVX2(W_0,W_2,W_4,W_6,W_8,W_10,W_12,W_14,a,b,c,d,e,f,g,h,i) \
            RND_0_1(a,b,c,d,e,f,g,h,i)                                       \
    VPALIGNR(W_Y_M15, W_2, W_0, 8)                                           \
    VPALIGNR(W_Y_M7, W_10, W_8, 8)                                           \
            RND_0_2(a,b,c,d,e,f,g,h,i)                                       \
    V_SHIFT_R(YTMP1, W_Y_M15, 1)                                             \
    V_SHIFT_L(YTMP2, W_Y_M15, 63)                                            \
            RND_0_3(a,b,c,d,e,f,g,h,i)                                       \
            RND_0_4(a,b,c,d,e,f,g,h,i)                                       \
    V_SHIFT_R(YTMP3, W_Y_M15, 8)                                             \
    V_SHIFT_L(YTMP4, W_Y_M15, 56)                                            \
            RND_0_5(a,b,c,d,e,f,g,h,i)                                       \
            RND_0_6(a,b,c,d,e,f,g,h,i)                                       \
    V_OR(YTMP1, YTMP2, YTMP1)                                                \
    V_OR(YTMP3, YTMP4, YTMP3)                                                \
            RND_0_7(a,b,c,d,e,f,g,h,i)                                       \
            RND_0_8(a,b,c,d,e,f,g,h,i)                                       \
    V_SHIFT_R(YTMP4, W_Y_M15, 7)                                             \
    V_XOR(YTMP1, YTMP3, YTMP1)                                               \
            RND_0_9(a,b,c,d,e,f,g,h,i)                                       \
            RND_0_10(a,b,c,d,e,f,g,h,i)                                      \
    V_XOR(YTMP1, YTMP4, YTMP1)                                               \
    V_ADD(W_0, W_0, W_Y_M7)                                                  \
            RND_0_11(a,b,c,d,e,f,g,h,i)                                      \
            RND_0_12(a,b,c,d,e,f,g,h,i)                                      \
            RND_1_1(h,a,b,c,d,e,f,g,i+1)                                     \
    V_ADD(W_0, W_0, YTMP1)                                                   \
            RND_1_2(h,a,b,c,d,e,f,g,i+1)                                     \
    V_SHIFT_R(YTMP1, W_14, 19)                                               \
    V_SHIFT_L(YTMP2, W_14, 45)                                               \
            RND_1_3(h,a,b,c,d,e,f,g,i+1)                                     \
            RND_1_4(h,a,b,c,d,e,f,g,i+1)                                     \
    V_SHIFT_R(YTMP3, W_14, 61)                                               \
    V_SHIFT_L(YTMP4, W_14, 3)                                                \
            RND_1_5(h,a,b,c,d,e,f,g,i+1)                                     \
            RND_1_6(h,a,b,c,d,e,f,g,i+1)                                     \
            RND_1_7(h,a,b,c,d,e,f,g,i+1)                                     \
    V_OR(YTMP1, YTMP2, YTMP1)                                                \
    V_OR(YTMP3, YTMP4, YTMP3)                                                \
            RND_1_8(h,a,b,c,d,e,f,g,i+1)                                     \
            RND_1_9(h,a,b,c,d,e,f,g,i+1)                                     \
    V_XOR(YTMP1, YTMP3, YTMP1)                                               \
    V_SHIFT_R(YTMP4, W_14, 6)                                                \
            RND_1_10(h,a,b,c,d,e,f,g,i+1)                                    \
            RND_1_11(h,a,b,c,d,e,f,g,i+1)                                    \
    V_XOR(YTMP1, YTMP4, YTMP1)                                               \
            RND_1_12(h,a,b,c,d,e,f,g,i+1)                                    \
    V_ADD(W_0, W_0, YTMP1)                                                   \

#define MsgSched4_AVX2_RORX_SET(W_Y_0,W_Y_4,W_Y_8,W_Y_12,a,b,c,d,e,f,g,h,i) \
            RND_RORX_0_1(a,b,c,d,e,f,g,h,i)                                 \
    /* W[-13]..W[-15], W[-12] */                                            \
    VPBLENDD(W_Y_M15, W_Y_0, W_Y_4, 0x03)                                   \
    /* W[-5]..W[-7], W[-4] */                                               \
    VPBLENDD(W_Y_M7, W_Y_8, W_Y_12, 0x03)                                   \
            RND_RORX_0_2(a,b,c,d,e,f,g,h,i)                                 \
    /* W_Y_M15 = W[-12]..W[-15] */                                          \
    VPERMQ(W_Y_M15, W_Y_M15, 0x39)                                          \
            RND_RORX_0_3(a,b,c,d,e,f,g,h,i)                                 \
    /* W_Y_M7 = W[-4]..W[-7] */                                             \
    VPERMQ(W_Y_M7, W_Y_M7, 0x39)                                            \
            RND_RORX_0_4(a,b,c,d,e,f,g,h,i)                                 \
    /* W[-15] >>  1 */                                                      \
    V_SHIFT_R(YTMP1, W_Y_M15, 1)                                            \
    /* W[-15] << 63 */                                                      \
    V_SHIFT_L(YTMP2, W_Y_M15, 63)                                           \
            RND_RORX_0_5(a,b,c,d,e,f,g,h,i)                                 \
    /* W[-15] >>  8 */                                                      \
    V_SHIFT_R(YTMP3, W_Y_M15, 8)                                            \
    /* W[-15] << 56 */                                                      \
    V_SHIFT_L(YTMP4, W_Y_M15, 56)                                           \
    /* W[-15] >>> 1 */                                                      \
    V_OR(YTMP1, YTMP2, YTMP1)                                               \
    /* W[-15] >>> 8 */                                                      \
    V_OR(YTMP3, YTMP4, YTMP3)                                               \
            RND_RORX_0_6(a,b,c,d,e,f,g,h,i)                                 \
    /* W[-15] >> 7 */                                                       \
    V_SHIFT_R(YTMP4, W_Y_M15, 7)                                            \
            RND_RORX_0_7(a,b,c,d,e,f,g,h,i)                                 \
    /* 0, 0, W[-1], W[-2] */                                                \
    VPERM2I128(W_Y_M2, W_Y_12, W_Y_12, 0x81)                                \
            RND_RORX_0_8(a,b,c,d,e,f,g,h,i)                                 \
            RND_RORX_1_1(h,a,b,c,d,e,f,g,i+1)                               \
    /* (W[-15] >>> 1) ^ (W[-15] >>> 8) */                                   \
    V_XOR(YTMP1, YTMP3, YTMP1)                                              \
            RND_RORX_1_2(h,a,b,c,d,e,f,g,i+1)                               \
    /* (W[-15] >>> 1) ^ (W[-15] >>> 8) ^ (W[-15] >> 7) */                   \
    V_XOR(YTMP1, YTMP4, YTMP1)                                              \
            RND_RORX_1_3(h,a,b,c,d,e,f,g,i+1)                               \
    /* W[0] = W[-16] + W[-7] */                                             \
    V_ADD(W_Y_0, W_Y_0, W_Y_M7)                                             \
    /* W[0] = W[-16] + W[-7] + s0(W[-15]) */                                \
    V_ADD(W_Y_0, W_Y_0, YTMP1)                                              \
            RND_RORX_1_4(h,a,b,c,d,e,f,g,i+1)                               \
    /* W[-2] >> 19 */                                                       \
    V_SHIFT_R(YTMP1, W_Y_M2, 19)                                            \
    /* W[-2] << 45 */                                                       \
    V_SHIFT_L(YTMP2, W_Y_M2, 45)                                            \
            RND_RORX_1_5(h,a,b,c,d,e,f,g,i+1)                               \
    /* W[-2] >> 61 */                                                       \
    V_SHIFT_R(YTMP3, W_Y_M2, 61)                                            \
    /* W[-2] <<  3 */                                                       \
    V_SHIFT_L(YTMP4, W_Y_M2, 3)                                             \
    /* W[-2] >>> 19 */                                                      \
    V_OR(YTMP1, YTMP2, YTMP1)                                               \
            RND_RORX_1_6(h,a,b,c,d,e,f,g,i+1)                               \
    /* W[-2] >>> 61 */                                                      \
    V_OR(YTMP3, YTMP4, YTMP3)                                               \
            RND_RORX_1_7(h,a,b,c,d,e,f,g,i+1)                               \
    /* (W[-2] >>> 19) ^ (W[-2] >>> 61) */                                   \
    V_XOR(YTMP1, YTMP3, YTMP1)                                              \
            RND_RORX_1_8(h,a,b,c,d,e,f,g,i+1)                               \
    /* W[-2] >>  6 */                                                       \
    V_SHIFT_R(YTMP4, W_Y_M2, 6)                                             \
            RND_RORX_0_1(g,h,a,b,c,d,e,f,i+2)                               \
    /* (W[-2] >>> 19) ^ (W[-2] >>> 61) ^ (W[-2] >> 6) */                    \
    V_XOR(YTMP1, YTMP4, YTMP1)                                              \
            RND_RORX_0_2(g,h,a,b,c,d,e,f,i+2)                               \
    /* W[0] = W[-16] + W[-7] + s0(W[-15]) + s1(W[-2]) */                    \
    V_ADD(W_Y_0, W_Y_0, YTMP1)                                              \
            RND_RORX_0_3(g,h,a,b,c,d,e,f,i+2)                               \
    /* W[1], W[0], 0, 0 */                                                  \
    VPERM2I128(W_Y_M2, W_Y_0, W_Y_0, 0x08)                                  \
            RND_RORX_0_4(g,h,a,b,c,d,e,f,i+2)                               \
            RND_RORX_0_5(g,h,a,b,c,d,e,f,i+2)                               \
    /* W[-2] >> 19 */                                                       \
    V_SHIFT_R(YTMP1, W_Y_M2, 19)                                            \
    /* W[-2] << 45 */                                                       \
    V_SHIFT_L(YTMP2, W_Y_M2, 45)                                            \
            RND_RORX_0_6(g,h,a,b,c,d,e,f,i+2)                               \
    /* W[-2] >> 61 */                                                       \
    V_SHIFT_R(YTMP3, W_Y_M2, 61)                                            \
    /* W[-2] <<  3 */                                                       \
    V_SHIFT_L(YTMP4, W_Y_M2, 3)                                             \
    /* W[-2] >>> 19 */                                                      \
    V_OR(YTMP1, YTMP2, YTMP1)                                               \
            RND_RORX_0_7(g,h,a,b,c,d,e,f,i+2)                               \
    /* W[-2] >>> 61 */                                                      \
    V_OR(YTMP3, YTMP4, YTMP3)                                               \
            RND_RORX_0_8(g,h,a,b,c,d,e,f,i+2)                               \
    /* (W[-2] >>> 19) ^ (W[-2] >>> 61) */                                   \
    V_XOR(YTMP1, YTMP3, YTMP1)                                              \
            RND_RORX_1_1(f,g,h,a,b,c,d,e,i+3)                               \
    /* W[-2] >>  6 */                                                       \
    V_SHIFT_R(YTMP4, W_Y_M2, 6)                                             \
            RND_RORX_1_2(f,g,h,a,b,c,d,e,i+3)                               \
            RND_RORX_1_3(f,g,h,a,b,c,d,e,i+3)                               \
    /* (W[-2] >>> 19) ^ (W[-2] >>> 61) ^ (W[-2] >> 6) */                    \
    V_XOR(YTMP1, YTMP4, YTMP1)                                              \
            RND_RORX_1_4(f,g,h,a,b,c,d,e,i+3)                               \
            RND_RORX_1_5(f,g,h,a,b,c,d,e,i+3)                               \
    /* W[0] = W[-16] + W[-7] + s0(W[-15]) + s1(W[-2]) */                    \
    V_ADD(W_Y_0, W_Y_0, YTMP1)                                              \
            RND_RORX_1_6(f,g,h,a,b,c,d,e,i+3)                               \
    V_ADD_I(YTMP1, W_Y_0, rsi, i)                                           \
            RND_RORX_1_7(f,g,h,a,b,c,d,e,i+3)                               \
            RND_RORX_1_8(f,g,h,a,b,c,d,e,i+3)                               \
    VMOVDQU_I(rsp, i, YTMP1)                                                \

#define MsgSched2_AVX2_RORX(W_0,W_2,W_4,W_6,W_8,W_10,W_12,W_14,a,b,c,d,e,  \
                            f,g,h,i)                                       \
            RND_RORX_0_1(a,b,c,d,e,f,g,h,i)                                \
    VPALIGNR(W_Y_M15, W_2, W_0, 8)                                         \
    VPALIGNR(W_Y_M7, W_10, W_8, 8)                                         \
            RND_RORX_0_2(a,b,c,d,e,f,g,h,i)                                \
    V_SHIFT_R(YTMP1, W_Y_M15, 1)                                           \
    V_SHIFT_L(YTMP2, W_Y_M15, 63)                                          \
            RND_RORX_0_3(a,b,c,d,e,f,g,h,i)                                \
    V_SHIFT_R(YTMP3, W_Y_M15, 8)                                           \
    V_SHIFT_L(YTMP4, W_Y_M15, 56)                                          \
            RND_RORX_0_4(a,b,c,d,e,f,g,h,i)                                \
    V_OR(YTMP1, YTMP2, YTMP1)                                              \
    V_OR(YTMP3, YTMP4, YTMP3)                                              \
            RND_RORX_0_5(a,b,c,d,e,f,g,h,i)                                \
    V_SHIFT_R(YTMP4, W_Y_M15, 7)                                           \
    V_XOR(YTMP1, YTMP3, YTMP1)                                             \
            RND_RORX_0_6(a,b,c,d,e,f,g,h,i)                                \
    V_XOR(YTMP1, YTMP4, YTMP1)                                             \
    V_ADD(W_0, W_0, W_Y_M7)                                                \
            RND_RORX_0_7(a,b,c,d,e,f,g,h,i)                                \
            RND_RORX_0_8(a,b,c,d,e,f,g,h,i)                                \
    V_ADD(W_0, W_0, YTMP1)                                                 \
            RND_RORX_1_1(h,a,b,c,d,e,f,g,i+1)                              \
    V_SHIFT_R(YTMP1, W_14, 19)                                             \
    V_SHIFT_L(YTMP2, W_14, 45)                                             \
            RND_RORX_1_2(h,a,b,c,d,e,f,g,i+1)                              \
    V_SHIFT_R(YTMP3, W_14, 61)                                             \
    V_SHIFT_L(YTMP4, W_14, 3)                                              \
            RND_RORX_1_3(h,a,b,c,d,e,f,g,i+1)                              \
    V_OR(YTMP1, YTMP2, YTMP1)                                              \
    V_OR(YTMP3, YTMP4, YTMP3)                                              \
            RND_RORX_1_4(h,a,b,c,d,e,f,g,i+1)                              \
            RND_RORX_1_5(h,a,b,c,d,e,f,g,i+1)                              \
    V_XOR(YTMP1, YTMP3, YTMP1)                                             \
    V_SHIFT_R(YTMP4, W_14, 6)                                              \
            RND_RORX_1_6(h,a,b,c,d,e,f,g,i+1)                              \
            RND_RORX_1_7(h,a,b,c,d,e,f,g,i+1)                              \
    V_XOR(YTMP1, YTMP4, YTMP1)                                             \
            RND_RORX_1_8(h,a,b,c,d,e,f,g,i+1)                              \
    V_ADD(W_0, W_0, YTMP1)                                                 \


#define _INIT_MASK_Y(mask)            \
    "vmovdqu %[mask], %%"#mask"\n\t"
#define INIT_MASK_Y(mask) \
       _INIT_MASK_Y(mask)

/* Load into YMM registers and swap endian. */
#define _LOAD_BLOCK_W_Y_2(mask, ymm0, ymm1, reg, i)     \
    /* buffer[0..15] => ymm0..ymm3;  */                 \
    "vmovdqu	"#i"+ 0(%%"#reg"), %%"#ymm0"\n\t"       \
    "vmovdqu	"#i"+32(%%"#reg"), %%"#ymm1"\n\t"       \
    "vpshufb	%%"#mask", %%"#ymm0", %%"#ymm0"\n\t"    \
    "vpshufb	%%"#mask", %%"#ymm1", %%"#ymm1"\n\t"

#define LOAD_BLOCK_W_Y_2(mask, ymm1, ymm2, reg, i) \
       _LOAD_BLOCK_W_Y_2(mask, ymm1, ymm2, reg, i)

#define LOAD_BLOCK_W_Y(mask, reg)                  \
    LOAD_BLOCK_W_Y_2(mask, W_Y_0, W_Y_4 , reg,  0) \
    LOAD_BLOCK_W_Y_2(mask, W_Y_8, W_Y_12, reg, 64)

#define _SET_W_Y_2(ymm0, ymm1, ymm2, ymm3, reg, i)            \
    "vpaddq	"#i"+ 0(%%"#reg"), %%"#ymm0", %%"#ymm2"\n\t"  \
    "vpaddq	"#i"+32(%%"#reg"), %%"#ymm1", %%"#ymm3"\n\t"  \
    "vmovdqu	%%"#ymm2", "#i"+ 0("WX")\n\t"                 \
    "vmovdqu	%%"#ymm3", "#i"+32("WX")\n\t"

#define SET_W_Y_2(ymm0, ymm1, ymm2, ymm3, reg, i) \
       _SET_W_Y_2(ymm0, ymm1, ymm2, ymm3, reg, i)

#define SET_BLOCK_W_Y(reg)                          \
    SET_W_Y_2(W_Y_0, W_Y_4 , YTMP1, YTMP2, reg,  0) \
    SET_W_Y_2(W_Y_8, W_Y_12, YTMP1, YTMP2, reg, 64)

/* Load into YMM registers and swap endian. */
#define _LOAD_BLOCK2_W_Y_2(mask, Y0, Y1, X0, X1, X8, X9, reg, i)   \
    "vmovdqu	"#i"+  0(%%"#reg"), %%"#X0"\n\t"                   \
    "vmovdqu	"#i"+ 16(%%"#reg"), %%"#X1"\n\t"                   \
    "vmovdqu	"#i"+128(%%"#reg"), %%"#X8"\n\t"                   \
    "vmovdqu	"#i"+144(%%"#reg"), %%"#X9"\n\t"                   \
    "vinserti128	$1, %%"#X8", %%"#Y0", %%"#Y0"\n\t"         \
    "vinserti128	$1, %%"#X9", %%"#Y1", %%"#Y1"\n\t"         \
    "vpshufb	%%"#mask", %%"#Y0", %%"#Y0"\n\t"                   \
    "vpshufb	%%"#mask", %%"#Y1", %%"#Y1"\n\t"

#define LOAD_BLOCK2_W_Y_2(mask, Y0, Y1, X0, X1, X8, X9, reg, i) \
       _LOAD_BLOCK2_W_Y_2(mask, Y0, Y1, X0, X1, X8, X9, reg, i)

#define LOAD_BLOCK2_W_Y(mask, reg)                           \
    LOAD_BLOCK2_W_Y_2(mask, Y0, Y1, X0, X1, X8, X9, reg,  0) \
    LOAD_BLOCK2_W_Y_2(mask, Y2, Y3, X2, X3, X8, X9, reg, 32) \
    LOAD_BLOCK2_W_Y_2(mask, Y4, Y5, X4, X5, X8, X9, reg, 64) \
    LOAD_BLOCK2_W_Y_2(mask, Y6, Y7, X6, X7, X8, X9, reg, 96) \

#define SET_BLOCK2_W_Y(reg)                   \
    SET_W_Y_2(Y0, Y1, YTMP1, YTMP2, reg,   0) \
    SET_W_Y_2(Y2, Y3, YTMP1, YTMP2, reg,  64) \
    SET_W_Y_2(Y4, Y5, YTMP1, YTMP2, reg, 128) \
    SET_W_Y_2(Y6, Y7, YTMP1, YTMP2, reg, 192)

static const word64 K512_AVX2[160] = {
    W64LIT(0x428a2f98d728ae22), W64LIT(0x7137449123ef65cd),
    W64LIT(0x428a2f98d728ae22), W64LIT(0x7137449123ef65cd),
    W64LIT(0xb5c0fbcfec4d3b2f), W64LIT(0xe9b5dba58189dbbc),
    W64LIT(0xb5c0fbcfec4d3b2f), W64LIT(0xe9b5dba58189dbbc),
    W64LIT(0x3956c25bf348b538), W64LIT(0x59f111f1b605d019),
    W64LIT(0x3956c25bf348b538), W64LIT(0x59f111f1b605d019),
    W64LIT(0x923f82a4af194f9b), W64LIT(0xab1c5ed5da6d8118),
    W64LIT(0x923f82a4af194f9b), W64LIT(0xab1c5ed5da6d8118),
    W64LIT(0xd807aa98a3030242), W64LIT(0x12835b0145706fbe),
    W64LIT(0xd807aa98a3030242), W64LIT(0x12835b0145706fbe),
    W64LIT(0x243185be4ee4b28c), W64LIT(0x550c7dc3d5ffb4e2),
    W64LIT(0x243185be4ee4b28c), W64LIT(0x550c7dc3d5ffb4e2),
    W64LIT(0x72be5d74f27b896f), W64LIT(0x80deb1fe3b1696b1),
    W64LIT(0x72be5d74f27b896f), W64LIT(0x80deb1fe3b1696b1),
    W64LIT(0x9bdc06a725c71235), W64LIT(0xc19bf174cf692694),
    W64LIT(0x9bdc06a725c71235), W64LIT(0xc19bf174cf692694),
    W64LIT(0xe49b69c19ef14ad2), W64LIT(0xefbe4786384f25e3),
    W64LIT(0xe49b69c19ef14ad2), W64LIT(0xefbe4786384f25e3),
    W64LIT(0x0fc19dc68b8cd5b5), W64LIT(0x240ca1cc77ac9c65),
    W64LIT(0x0fc19dc68b8cd5b5), W64LIT(0x240ca1cc77ac9c65),
    W64LIT(0x2de92c6f592b0275), W64LIT(0x4a7484aa6ea6e483),
    W64LIT(0x2de92c6f592b0275), W64LIT(0x4a7484aa6ea6e483),
    W64LIT(0x5cb0a9dcbd41fbd4), W64LIT(0x76f988da831153b5),
    W64LIT(0x5cb0a9dcbd41fbd4), W64LIT(0x76f988da831153b5),
    W64LIT(0x983e5152ee66dfab), W64LIT(0xa831c66d2db43210),
    W64LIT(0x983e5152ee66dfab), W64LIT(0xa831c66d2db43210),
    W64LIT(0xb00327c898fb213f), W64LIT(0xbf597fc7beef0ee4),
    W64LIT(0xb00327c898fb213f), W64LIT(0xbf597fc7beef0ee4),
    W64LIT(0xc6e00bf33da88fc2), W64LIT(0xd5a79147930aa725),
    W64LIT(0xc6e00bf33da88fc2), W64LIT(0xd5a79147930aa725),
    W64LIT(0x06ca6351e003826f), W64LIT(0x142929670a0e6e70),
    W64LIT(0x06ca6351e003826f), W64LIT(0x142929670a0e6e70),
    W64LIT(0x27b70a8546d22ffc), W64LIT(0x2e1b21385c26c926),
    W64LIT(0x27b70a8546d22ffc), W64LIT(0x2e1b21385c26c926),
    W64LIT(0x4d2c6dfc5ac42aed), W64LIT(0x53380d139d95b3df),
    W64LIT(0x4d2c6dfc5ac42aed), W64LIT(0x53380d139d95b3df),
    W64LIT(0x650a73548baf63de), W64LIT(0x766a0abb3c77b2a8),
    W64LIT(0x650a73548baf63de), W64LIT(0x766a0abb3c77b2a8),
    W64LIT(0x81c2c92e47edaee6), W64LIT(0x92722c851482353b),
    W64LIT(0x81c2c92e47edaee6), W64LIT(0x92722c851482353b),
    W64LIT(0xa2bfe8a14cf10364), W64LIT(0xa81a664bbc423001),
    W64LIT(0xa2bfe8a14cf10364), W64LIT(0xa81a664bbc423001),
    W64LIT(0xc24b8b70d0f89791), W64LIT(0xc76c51a30654be30),
    W64LIT(0xc24b8b70d0f89791), W64LIT(0xc76c51a30654be30),
    W64LIT(0xd192e819d6ef5218), W64LIT(0xd69906245565a910),
    W64LIT(0xd192e819d6ef5218), W64LIT(0xd69906245565a910),
    W64LIT(0xf40e35855771202a), W64LIT(0x106aa07032bbd1b8),
    W64LIT(0xf40e35855771202a), W64LIT(0x106aa07032bbd1b8),
    W64LIT(0x19a4c116b8d2d0c8), W64LIT(0x1e376c085141ab53),
    W64LIT(0x19a4c116b8d2d0c8), W64LIT(0x1e376c085141ab53),
    W64LIT(0x2748774cdf8eeb99), W64LIT(0x34b0bcb5e19b48a8),
    W64LIT(0x2748774cdf8eeb99), W64LIT(0x34b0bcb5e19b48a8),
    W64LIT(0x391c0cb3c5c95a63), W64LIT(0x4ed8aa4ae3418acb),
    W64LIT(0x391c0cb3c5c95a63), W64LIT(0x4ed8aa4ae3418acb),
    W64LIT(0x5b9cca4f7763e373), W64LIT(0x682e6ff3d6b2b8a3),
    W64LIT(0x5b9cca4f7763e373), W64LIT(0x682e6ff3d6b2b8a3),
    W64LIT(0x748f82ee5defb2fc), W64LIT(0x78a5636f43172f60),
    W64LIT(0x748f82ee5defb2fc), W64LIT(0x78a5636f43172f60),
    W64LIT(0x84c87814a1f0ab72), W64LIT(0x8cc702081a6439ec),
    W64LIT(0x84c87814a1f0ab72), W64LIT(0x8cc702081a6439ec),
    W64LIT(0x90befffa23631e28), W64LIT(0xa4506cebde82bde9),
    W64LIT(0x90befffa23631e28), W64LIT(0xa4506cebde82bde9),
    W64LIT(0xbef9a3f7b2c67915), W64LIT(0xc67178f2e372532b),
    W64LIT(0xbef9a3f7b2c67915), W64LIT(0xc67178f2e372532b),
    W64LIT(0xca273eceea26619c), W64LIT(0xd186b8c721c0c207),
    W64LIT(0xca273eceea26619c), W64LIT(0xd186b8c721c0c207),
    W64LIT(0xeada7dd6cde0eb1e), W64LIT(0xf57d4f7fee6ed178),
    W64LIT(0xeada7dd6cde0eb1e), W64LIT(0xf57d4f7fee6ed178),
    W64LIT(0x06f067aa72176fba), W64LIT(0x0a637dc5a2c898a6),
    W64LIT(0x06f067aa72176fba), W64LIT(0x0a637dc5a2c898a6),
    W64LIT(0x113f9804bef90dae), W64LIT(0x1b710b35131c471b),
    W64LIT(0x113f9804bef90dae), W64LIT(0x1b710b35131c471b),
    W64LIT(0x28db77f523047d84), W64LIT(0x32caab7b40c72493),
    W64LIT(0x28db77f523047d84), W64LIT(0x32caab7b40c72493),
    W64LIT(0x3c9ebe0a15c9bebc), W64LIT(0x431d67c49c100d4c),
    W64LIT(0x3c9ebe0a15c9bebc), W64LIT(0x431d67c49c100d4c),
    W64LIT(0x4cc5d4becb3e42b6), W64LIT(0x597f299cfc657e2a),
    W64LIT(0x4cc5d4becb3e42b6), W64LIT(0x597f299cfc657e2a),
    W64LIT(0x5fcb6fab3ad6faec), W64LIT(0x6c44198c4a475817),
    W64LIT(0x5fcb6fab3ad6faec), W64LIT(0x6c44198c4a475817)
};
static const word64* K512_AVX2_END = &K512_AVX2[128];

static int Transform_Sha512_AVX2(wc_Sha512* sha512)
{
    __asm__ __volatile__ (

        /* 16 Ws plus loop counter and K512. */
        "subq	$136, %%rsp\n\t"
        "leaq	64(%[sha512]), %%rax\n\t"

    INIT_MASK(MASK_Y)
    LOAD_DIGEST()

    LOAD_BLOCK_W_Y(MASK_Y, rax)

        "movl	$4, 16*8("WX")\n\t"
        "leaq	%[K512], %%rsi\n\t"
        /* b */
        "movq	%%r9, "L4"\n\t"
        /* e */
        "movq	%%r12, "L1"\n\t"
        /* b ^ c */
        "xorq	%%r10, "L4"\n\t"

    SET_BLOCK_W_Y(rsi)

        "# Start of 16 rounds\n"
        "1:\n\t"

        "addq	$128, %%rsi\n\t"

    MsgSched4_AVX2(W_Y_0,W_Y_4,W_Y_8,W_Y_12,RA,RB,RC,RD,RE,RF,RG,RH, 0)
    MsgSched4_AVX2(W_Y_4,W_Y_8,W_Y_12,W_Y_0,RE,RF,RG,RH,RA,RB,RC,RD, 4)
    MsgSched4_AVX2(W_Y_8,W_Y_12,W_Y_0,W_Y_4,RA,RB,RC,RD,RE,RF,RG,RH, 8)
    MsgSched4_AVX2(W_Y_12,W_Y_0,W_Y_4,W_Y_8,RE,RF,RG,RH,RA,RB,RC,RD,12)

    SET_BLOCK_W_Y(rsi)

        "subl	$1, 16*8("WX")\n\t"
        "jne	1b\n\t"

    RND_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH, 0)
    RND_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF, 2)
    RND_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD, 4)
    RND_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB, 6)

    RND_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH, 8)
    RND_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF,10)
    RND_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD,12)
    RND_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB,14)

    STORE_ADD_DIGEST()

        "addq	$136, %%rsp\n\t"

        :
        : [mask]   "m" (mBYTE_FLIP_MASK_Y),
          [sha512] "r" (sha512),
          [K512]   "m" (K512)
        : WORK_REGS, STATE_REGS, YMM_REGS, "memory", "rsi"
    );

    return 0;
}

static int Transform_Sha512_AVX2_Len(wc_Sha512* sha512, word32 len)
{
    if ((len & WC_SHA512_BLOCK_SIZE) != 0) {
        XMEMCPY(sha512->buffer, sha512->data, WC_SHA512_BLOCK_SIZE);
        Transform_Sha512_AVX2(sha512);
        sha512->data += WC_SHA512_BLOCK_SIZE;
        len -= WC_SHA512_BLOCK_SIZE;
        if (len == 0)
            return 0;
    }

    __asm__ __volatile__ (

        "movq	224(%[sha512]), %%rcx\n\t"

    INIT_MASK(MASK_Y)
    LOAD_DIGEST()

        "# Start of processing two blocks\n"
        "2:\n\t"

        "subq	$1344, %%rsp\n\t"
        "leaq	%[K512], %%rsi\n\t"

        /* L4 = b */
        "movq	%%r9, "L4"\n\t"
        /* e */
        "movq	%%r12, "L1"\n\t"

    LOAD_BLOCK2_W_Y(MASK_Y, rcx)

        /* L4 = b ^ c */
        "xorq	%%r10, "L4"\n\t"
        "\n"
        "1:\n\t"
    SET_BLOCK2_W_Y(rsi)
    MsgSched2_AVX2(Y0,Y1,Y2,Y3,Y4,Y5,Y6,Y7,RA,RB,RC,RD,RE,RF,RG,RH, 0)
    MsgSched2_AVX2(Y1,Y2,Y3,Y4,Y5,Y6,Y7,Y0,RG,RH,RA,RB,RC,RD,RE,RF, 4)
    MsgSched2_AVX2(Y2,Y3,Y4,Y5,Y6,Y7,Y0,Y1,RE,RF,RG,RH,RA,RB,RC,RD, 8)
    MsgSched2_AVX2(Y3,Y4,Y5,Y6,Y7,Y0,Y1,Y2,RC,RD,RE,RF,RG,RH,RA,RB,12)
    MsgSched2_AVX2(Y4,Y5,Y6,Y7,Y0,Y1,Y2,Y3,RA,RB,RC,RD,RE,RF,RG,RH,16)
    MsgSched2_AVX2(Y5,Y6,Y7,Y0,Y1,Y2,Y3,Y4,RG,RH,RA,RB,RC,RD,RE,RF,20)
    MsgSched2_AVX2(Y6,Y7,Y0,Y1,Y2,Y3,Y4,Y5,RE,RF,RG,RH,RA,RB,RC,RD,24)
    MsgSched2_AVX2(Y7,Y0,Y1,Y2,Y3,Y4,Y5,Y6,RC,RD,RE,RF,RG,RH,RA,RB,28)
        "addq	$256, %%rsi\n\t"
        "addq	$256, %%rsp\n\t"
        "cmpq	%[K512_END], %%rsi\n\t"
        "jne	1b\n\t"

    SET_BLOCK2_W_Y(rsi)
    RND_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH, 0)
    RND_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF, 4)
    RND_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD, 8)
    RND_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB,12)

    RND_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH,16)
    RND_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF,20)
    RND_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD,24)
    RND_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB,28)
        "subq	$1024, %%rsp\n\t"

    ADD_DIGEST()
    STORE_DIGEST()

        /* L4 = b */
        "movq	%%r9, "L4"\n\t"
        /* e */
        "movq	%%r12, "L1"\n\t"
        /* L4 = b ^ c */
        "xorq	%%r10, "L4"\n\t"

        "movq	$5, %%rsi\n\t"
        "\n"
        "3:\n\t"
    RND_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH, 2)
    RND_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF, 6)
    RND_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD,10)
    RND_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB,14)

    RND_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH,18)
    RND_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF,22)
    RND_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD,26)
    RND_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB,30)
        "addq	$256, %%rsp\n\t"
        "subq	$1, %%rsi\n\t"
        "jnz	3b\n\t"

    ADD_DIGEST()

        "movq	224(%[sha512]), %%rcx\n\t"
        "addq	$64, %%rsp\n\t"
        "addq	$256, %%rcx\n\t"
        "subl	$256, %[len]\n\t"
        "movq	%%rcx, 224(%[sha512])\n\t"

    STORE_DIGEST()

        "jnz	2b\n\t"

        :
        : [mask]   "m" (mBYTE_FLIP_MASK_Y),
          [len]    "m" (len),
          [sha512] "r" (sha512),
          [K512]   "m" (K512_AVX2),
          [K512_END]   "m" (K512_AVX2_END)
        : WORK_REGS, STATE_REGS, YMM_REGS, "memory", "rsi"
    );

    return 0;
}

#ifdef HAVE_INTEL_RORX
static int Transform_Sha512_AVX2_RORX(wc_Sha512* sha512)
{
    __asm__ __volatile__ (

        /* 16 Ws plus loop counter. */
        "subq	$136, %%rsp\n\t"
        "leaq	64(%[sha512]), "L2"\n\t"

    INIT_MASK(MASK_Y)
    LOAD_DIGEST()

    LOAD_BLOCK_W_Y(MASK_Y, rcx)

        "movl	$4, 16*8("WX")\n\t"
        "leaq	%[K512], %%rsi\n\t"
        /* b */
        "movq	%%r9, "L4"\n\t"
        /* L3 = 0 (add to prev h) */
        "xorq	"L3", "L3"\n\t"
        /* b ^ c */
        "xorq	%%r10, "L4"\n\t"

    SET_BLOCK_W_Y(rsi)

        "# Start of 16 rounds\n"
        "1:\n\t"

        "addq	$128, %%rsi\n\t"

    MsgSched4_AVX2_RORX_SET(W_Y_0,W_Y_4,W_Y_8,W_Y_12,RA,RB,RC,RD,RE,RF,RG,RH, 0)
    MsgSched4_AVX2_RORX_SET(W_Y_4,W_Y_8,W_Y_12,W_Y_0,RE,RF,RG,RH,RA,RB,RC,RD, 4)
    MsgSched4_AVX2_RORX_SET(W_Y_8,W_Y_12,W_Y_0,W_Y_4,RA,RB,RC,RD,RE,RF,RG,RH, 8)
    MsgSched4_AVX2_RORX_SET(W_Y_12,W_Y_0,W_Y_4,W_Y_8,RE,RF,RG,RH,RA,RB,RC,RD,12)

        "subl	$1, 16*8(%%rsp)\n\t"
        "jnz	1b\n\t"

    RND_RORX_ALL_4(RA,RB,RC,RD,RE,RF,RG,RH, 0)
    RND_RORX_ALL_4(RE,RF,RG,RH,RA,RB,RC,RD, 4)
    RND_RORX_ALL_4(RA,RB,RC,RD,RE,RF,RG,RH, 8)
    RND_RORX_ALL_4(RE,RF,RG,RH,RA,RB,RC,RD,12)
        /* Prev RND: h += Maj(a,b,c) */
        "addq	"L3", %%r8\n\t"
        "addq	$136, %%rsp\n\t"

    STORE_ADD_DIGEST()

        :
        : [mask]   "m" (mBYTE_FLIP_MASK_Y),
          [sha512] "r" (sha512),
          [K512]   "m" (K512)
        : WORK_REGS, STATE_REGS, YMM_REGS, "memory", "rsi"
    );

    return 0;
}

static int Transform_Sha512_AVX2_RORX_Len(wc_Sha512* sha512, word32 len)
{
    if ((len & WC_SHA512_BLOCK_SIZE) != 0) {
        XMEMCPY(sha512->buffer, sha512->data, WC_SHA512_BLOCK_SIZE);
        Transform_Sha512_AVX2_RORX(sha512);
        sha512->data += WC_SHA512_BLOCK_SIZE;
        len -= WC_SHA512_BLOCK_SIZE;
        if (len == 0)
            return 0;
    }

    __asm__ __volatile__ (

        "movq	224(%[sha512]), %%rax\n\t"

    INIT_MASK(MASK_Y)
    LOAD_DIGEST()

        "# Start of processing two blocks\n"
        "2:\n\t"

        "subq	$1344, %%rsp\n\t"
        "leaq	%[K512], %%rsi\n\t"

        /* L4 = b */
        "movq	%%r9, "L4"\n\t"
        /* L3 = 0 (add to prev h) */
        "xorq	"L3", "L3"\n\t"

    LOAD_BLOCK2_W_Y(MASK_Y, rax)

        /* L4 = b ^ c */
        "xorq	%%r10, "L4"\n\t"
        "\n"
        "1:\n\t"
    SET_BLOCK2_W_Y(rsi)
    MsgSched2_AVX2_RORX(Y0,Y1,Y2,Y3,Y4,Y5,Y6,Y7,RA,RB,RC,RD,RE,RF,RG,RH, 0)
    MsgSched2_AVX2_RORX(Y1,Y2,Y3,Y4,Y5,Y6,Y7,Y0,RG,RH,RA,RB,RC,RD,RE,RF, 4)
    MsgSched2_AVX2_RORX(Y2,Y3,Y4,Y5,Y6,Y7,Y0,Y1,RE,RF,RG,RH,RA,RB,RC,RD, 8)
    MsgSched2_AVX2_RORX(Y3,Y4,Y5,Y6,Y7,Y0,Y1,Y2,RC,RD,RE,RF,RG,RH,RA,RB,12)
    MsgSched2_AVX2_RORX(Y4,Y5,Y6,Y7,Y0,Y1,Y2,Y3,RA,RB,RC,RD,RE,RF,RG,RH,16)
    MsgSched2_AVX2_RORX(Y5,Y6,Y7,Y0,Y1,Y2,Y3,Y4,RG,RH,RA,RB,RC,RD,RE,RF,20)
    MsgSched2_AVX2_RORX(Y6,Y7,Y0,Y1,Y2,Y3,Y4,Y5,RE,RF,RG,RH,RA,RB,RC,RD,24)
    MsgSched2_AVX2_RORX(Y7,Y0,Y1,Y2,Y3,Y4,Y5,Y6,RC,RD,RE,RF,RG,RH,RA,RB,28)
        "addq	$256, %%rsi\n\t"
        "addq	$256, %%rsp\n\t"
        "cmpq	%[K512_END], %%rsi\n\t"
        "jne	1b\n\t"

    SET_BLOCK2_W_Y(rsi)
    RND_RORX_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH, 0)
    RND_RORX_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF, 4)
    RND_RORX_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD, 8)
    RND_RORX_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB,12)

    RND_RORX_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH,16)
    RND_RORX_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF,20)
    RND_RORX_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD,24)
    RND_RORX_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB,28)
        "addq	"L3", %%r8\n\t"
        "subq	$1024, %%rsp\n\t"

    ADD_DIGEST()
    STORE_DIGEST()

        /* L4 = b */
        "movq	%%r9, "L4"\n\t"
        /* L3 = 0 (add to prev h) */
        "xorq	"L3", "L3"\n\t"
        /* L4 = b ^ c */
        "xorq	%%r10, "L4"\n\t"

        "movq	$5, %%rsi\n\t"
        "\n"
        "3:\n\t"
    RND_RORX_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH, 2)
    RND_RORX_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF, 6)
    RND_RORX_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD,10)
    RND_RORX_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB,14)

    RND_RORX_ALL_2(RA,RB,RC,RD,RE,RF,RG,RH,18)
    RND_RORX_ALL_2(RG,RH,RA,RB,RC,RD,RE,RF,22)
    RND_RORX_ALL_2(RE,RF,RG,RH,RA,RB,RC,RD,26)
    RND_RORX_ALL_2(RC,RD,RE,RF,RG,RH,RA,RB,30)
        "addq	$256, %%rsp\n\t"
        "subq	$1, %%rsi\n\t"
        "jnz	3b\n\t"

        "addq	"L3", %%r8\n\t"

    ADD_DIGEST()

        "movq	224(%[sha512]), %%rax\n\t"
        "addq	$64, %%rsp\n\t"
        "addq	$256, %%rax\n\t"
        "subl	$256, %[len]\n\t"
        "movq	%%rax, 224(%[sha512])\n\t"

    STORE_DIGEST()

        "jnz	2b\n\t"

        :
        : [mask]   "m" (mBYTE_FLIP_MASK_Y),
          [len]    "m" (len),
          [sha512] "r" (sha512),
          [K512]   "m" (K512_AVX2),
          [K512_END]   "m" (K512_AVX2_END)
        : WORK_REGS, STATE_REGS, YMM_REGS, "memory", "rsi"
    );

    return 0;
}
#endif /* HAVE_INTEL_RORX */
#endif /* HAVE_INTEL_AVX2 */



/* -------------------------------------------------------------------------- */
/* SHA384 */
/* -------------------------------------------------------------------------- */
#ifdef WOLFSSL_SHA384

#if defined(WOLFSSL_IMX6_CAAM) && !defined(NO_IMX6_CAAM_HASH)
    /* functions defined in wolfcrypt/src/port/caam/caam_sha.c */
#else

static int InitSha384(wc_Sha384* sha384)
{
    if (sha384 == NULL) {
        return BAD_FUNC_ARG;
    }

    sha384->digest[0] = W64LIT(0xcbbb9d5dc1059ed8);
    sha384->digest[1] = W64LIT(0x629a292a367cd507);
    sha384->digest[2] = W64LIT(0x9159015a3070dd17);
    sha384->digest[3] = W64LIT(0x152fecd8f70e5939);
    sha384->digest[4] = W64LIT(0x67332667ffc00b31);
    sha384->digest[5] = W64LIT(0x8eb44a8768581511);
    sha384->digest[6] = W64LIT(0xdb0c2e0d64f98fa7);
    sha384->digest[7] = W64LIT(0x47b5481dbefa4fa4);

    sha384->buffLen = 0;
    sha384->loLen   = 0;
    sha384->hiLen   = 0;

    return 0;
}

int wc_Sha384Update(wc_Sha384* sha384, const byte* data, word32 len)
{
    if (sha384 == NULL || (data == NULL && len > 0)) {
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA384)
    if (sha384->asyncDev.marker == WOLFSSL_ASYNC_MARKER_SHA384) {
    #if defined(HAVE_INTEL_QA)
        return IntelQaSymSha384(&sha384->asyncDev, NULL, data, len);
    #endif
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    return Sha512Update((wc_Sha512*)sha384, data, len);
}


int wc_Sha384Final(wc_Sha384* sha384, byte* hash)
{
    int ret;

    if (sha384 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA384)
    if (sha384->asyncDev.marker == WOLFSSL_ASYNC_MARKER_SHA384) {
    #if defined(HAVE_INTEL_QA)
        return IntelQaSymSha384(&sha384->asyncDev, hash, NULL,
                                            WC_SHA384_DIGEST_SIZE);
    #endif
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    ret = Sha512Final((wc_Sha512*)sha384);
    if (ret != 0)
        return ret;

    XMEMCPY(hash, sha384->digest, WC_SHA384_DIGEST_SIZE);

    return InitSha384(sha384);  /* reset state */
}


/* Hardware Acceleration */
#if defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2)
    int wc_InitSha384_ex(wc_Sha384* sha384, void* heap, int devId)
    {
        int ret = InitSha384(sha384);

        (void)heap;
        (void)devId;

        Sha512_SetTransform();

        return ret;
    }
#else
int wc_InitSha384_ex(wc_Sha384* sha384, void* heap, int devId)
{
    int ret;

    if (sha384 == NULL) {
        return BAD_FUNC_ARG;
    }

    sha384->heap = heap;
    ret = InitSha384(sha384);
    if (ret != 0)
        return ret;

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA384)
    ret = wolfAsync_DevCtxInit(&sha384->asyncDev, WOLFSSL_ASYNC_MARKER_SHA384,
                                                           sha384->heap, devId);
#else
    (void)devId;
#endif /* WOLFSSL_ASYNC_CRYPT */

    return ret;
}
#endif
#endif /* WOLFSSL_IMX6_CAAM */

int wc_InitSha384(wc_Sha384* sha384)
{
    return wc_InitSha384_ex(sha384, NULL, INVALID_DEVID);
}

void wc_Sha384Free(wc_Sha384* sha384)
{
    if (sha384 == NULL)
        return;

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA384)
    wolfAsync_DevCtxFree(&sha384->asyncDev, WOLFSSL_ASYNC_MARKER_SHA384);
#endif /* WOLFSSL_ASYNC_CRYPT */
}

#endif /* WOLFSSL_SHA384 */

#endif /* HAVE_FIPS */


int wc_Sha512GetHash(wc_Sha512* sha512, byte* hash)
{
    int ret;
    wc_Sha512 tmpSha512;

    if (sha512 == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    ret = wc_Sha512Copy(sha512, &tmpSha512);
    if (ret == 0) {
        ret = wc_Sha512Final(&tmpSha512, hash);
    }
    return ret;
}

int wc_Sha512Copy(wc_Sha512* src, wc_Sha512* dst)
{
    int ret = 0;

    if (src == NULL || dst == NULL)
        return BAD_FUNC_ARG;

    XMEMCPY(dst, src, sizeof(wc_Sha512));

#ifdef WOLFSSL_ASYNC_CRYPT
    ret = wolfAsync_DevCopy(&src->asyncDev, &dst->asyncDev);
#endif

    return ret;
}

#ifdef WOLFSSL_SHA384
int wc_Sha384GetHash(wc_Sha384* sha384, byte* hash)
{
    int ret;
    wc_Sha384 tmpSha384;

    if (sha384 == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    ret = wc_Sha384Copy(sha384, &tmpSha384);
    if (ret == 0) {
        ret = wc_Sha384Final(&tmpSha384, hash);
    }
    return ret;
}
int wc_Sha384Copy(wc_Sha384* src, wc_Sha384* dst)
{
    int ret = 0;

    if (src == NULL || dst == NULL)
        return BAD_FUNC_ARG;

    XMEMCPY(dst, src, sizeof(wc_Sha384));

#ifdef WOLFSSL_ASYNC_CRYPT
    ret = wolfAsync_DevCopy(&src->asyncDev, &dst->asyncDev);
#endif

    return ret;
}
#endif /* WOLFSSL_SHA384 */

#endif /* HAVE_FIPS && HAVE_FIPS_VERSION >= 2 && WOLFSSL_ARMASM */
#endif /* WOLFSSL_SHA512 */
