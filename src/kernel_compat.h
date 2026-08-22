/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LIBPOGOST_KERNEL_COMPAT_H
#define LIBPOGOST_KERNEL_COMPAT_H

#include <libpogost/blake2s.h>
#include <libpogost/chacha.h>
#include <libpogost/chacha20poly1305.h>
#include <libpogost/curve25519.h>
#include <libpogost/poly1305.h>

#ifdef __KERNEL__
#include <crypto/utils.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <linux/unroll.h>
#ifndef unrolled_full
#define unrolled_full
#endif
#ifndef at_least
#define at_least
#endif
#else
#include <limits.h>
#include <string.h>
#if defined(__linux__) || defined(__ANDROID__)
#include <linux/types.h>
#else
typedef u32 __le32;
typedef u64 __le64;
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline, unused))
#endif
#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif
#ifndef noinline
#define noinline __attribute__((noinline))
#endif
#define __aligned(x) __attribute__((aligned(x)))
#define __must_check __attribute__((warn_unused_result))
#define at_least
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define ARRAY_SIZE(x) ((int)(sizeof(x) / sizeof((x)[0])))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define round_down(x, y) ((x) - ((x) % (y)))
#define WARN_ON(x) do { (void)(x); } while (0)
#define WARN_ON_ONCE(x) WARN_ON(x)
#define IS_ENABLED(x) 0
#define unrolled_full
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define MODULE_LICENSE(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_AUTHOR(x)

static __maybe_unused __always_inline u32 ror32(u32 x, unsigned int n)
{
	return (x >> n) | (x << (32 - n));
}

static __maybe_unused __always_inline u32 rol32(u32 x, unsigned int n)
{
	return (x << n) | (x >> (32 - n));
}

static __maybe_unused __always_inline u32 get_unaligned_le32(const void *p)
{
	const u8 *b = p;
	return (u32)b[0] | (u32)b[1] << 8 | (u32)b[2] << 16 | (u32)b[3] << 24;
}

static __maybe_unused __always_inline u64 get_unaligned_le64(const void *p)
{
	const u8 *b = p;
	return (u64)get_unaligned_le32(b) | (u64)get_unaligned_le32(b + 4) << 32;
}

static __maybe_unused __always_inline void put_unaligned_le32(u32 v, void *p)
{
	u8 *b = p;
	b[0] = v;
	b[1] = v >> 8;
	b[2] = v >> 16;
	b[3] = v >> 24;
}

static __maybe_unused __always_inline void put_unaligned_le64(u64 v, void *p)
{
	put_unaligned_le32((u32)v, p);
	put_unaligned_le32((u32)(v >> 32), (u8 *)p + 4);
}

static __maybe_unused __always_inline u64 cpu_to_le64(u64 v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return v;
#else
	return __builtin_bswap64(v);
#endif
}

static __maybe_unused __always_inline void le32_to_cpu_array(u32 *p, unsigned int n)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	while (n--) { *p = __builtin_bswap32(*p); p++; }
#else
	(void)p; (void)n;
#endif
}

static __maybe_unused __always_inline void cpu_to_le32_array(u32 *p, unsigned int n)
{
	le32_to_cpu_array(p, n);
}

static __maybe_unused __always_inline void memzero_explicit(void *p, size_t n)
{
	volatile u8 *v = p;
	while (n--)
		*v++ = 0;
}

static __maybe_unused __always_inline void crypto_xor_cpy(u8 *dst, const u8 *a,
					   const u8 *b, size_t n)
{
	while (n--)
		*dst++ = *a++ ^ *b++;
}

static __maybe_unused __always_inline int crypto_memneq(const void *a, const void *b, size_t n)
{
	const u8 *x = a, *y = b;
	u8 d = 0;
	while (n--)
		d |= *x++ ^ *y++;
	return d != 0;
}

static const u8 pogost_zero_page[POGOST_CHACHA_BLOCK_SIZE] = { 0 };
#define ZERO_PAGE(x) (pogost_zero_page)
#define page_address(x) (x)
#endif

/* Keep imported Linux crypto source unchanged below its include block. */
#define blake2s_ctx pogost_blake2s_ctx
#define BLAKE2S_BLOCK_SIZE POGOST_BLAKE2S_BLOCK_SIZE
#define BLAKE2S_HASH_SIZE POGOST_BLAKE2S_HASH_SIZE
#define BLAKE2S_KEY_SIZE POGOST_BLAKE2S_KEY_SIZE
#define BLAKE2S_IV0 POGOST_BLAKE2S_IV0
#define BLAKE2S_IV1 POGOST_BLAKE2S_IV1
#define BLAKE2S_IV2 POGOST_BLAKE2S_IV2
#define BLAKE2S_IV3 POGOST_BLAKE2S_IV3
#define BLAKE2S_IV4 POGOST_BLAKE2S_IV4
#define BLAKE2S_IV5 POGOST_BLAKE2S_IV5
#define BLAKE2S_IV6 POGOST_BLAKE2S_IV6
#define BLAKE2S_IV7 POGOST_BLAKE2S_IV7
#define blake2s_update pogost_blake2s_update
#define blake2s_final pogost_blake2s_final

#define chacha_state pogost_chacha_state
#define CHACHA_IV_SIZE POGOST_CHACHA_IV_SIZE
#define CHACHA_KEY_SIZE POGOST_CHACHA_KEY_SIZE
#define CHACHA_BLOCK_SIZE POGOST_CHACHA_BLOCK_SIZE
#define CHACHAPOLY_IV_SIZE POGOST_CHACHAPOLY_IV_SIZE
#define CHACHA_KEY_WORDS POGOST_CHACHA_KEY_WORDS
#define CHACHA_STATE_WORDS POGOST_CHACHA_STATE_WORDS
#define HCHACHA_OUT_WORDS POGOST_HCHACHA_OUT_WORDS
#define XCHACHA_IV_SIZE POGOST_XCHACHA_IV_SIZE
#define CHACHA_CONSTANT_EXPA POGOST_CHACHA_CONSTANT_EXPA
#define CHACHA_CONSTANT_ND_3 POGOST_CHACHA_CONSTANT_ND_3
#define CHACHA_CONSTANT_2_BY POGOST_CHACHA_CONSTANT_2_BY
#define CHACHA_CONSTANT_TE_K POGOST_CHACHA_CONSTANT_TE_K
#define chacha_block_generic pogost_chacha_block_generic
#define hchacha_block_generic pogost_hchacha_block_generic
#define chacha_crypt pogost_chacha_crypt
#define chacha20_crypt pogost_chacha20_crypt
#define chacha_init pogost_chacha_init
#define chacha_zeroize_state pogost_chacha_zeroize_state
#define hchacha_block pogost_hchacha_block

#define poly1305_key pogost_poly1305_key
#define poly1305_core_key pogost_poly1305_core_key
#define poly1305_state pogost_poly1305_state
#define poly1305_block_state pogost_poly1305_block_state
#define poly1305_desc_ctx pogost_poly1305_desc_ctx
#define POLY1305_BLOCK_SIZE POGOST_POLY1305_BLOCK_SIZE
#define POLY1305_KEY_SIZE POGOST_POLY1305_KEY_SIZE
#define POLY1305_DIGEST_SIZE POGOST_POLY1305_DIGEST_SIZE
#define poly1305_core_setkey pogost_poly1305_core_setkey
#define poly1305_core_blocks pogost_poly1305_core_blocks
#define poly1305_core_emit pogost_poly1305_core_emit
#define poly1305_init pogost_poly1305_init
#define poly1305_update pogost_poly1305_update
#define poly1305_final pogost_poly1305_final

#define XCHACHA20POLY1305_NONCE_SIZE POGOST_XCHACHA20POLY1305_NONCE_SIZE
#define CHACHA20POLY1305_KEY_SIZE POGOST_CHACHA20POLY1305_KEY_SIZE
#define CHACHA20POLY1305_AUTHTAG_SIZE POGOST_CHACHA20POLY1305_AUTHTAG_SIZE
#define chacha20poly1305_encrypt pogost_chacha20poly1305_encrypt
#define chacha20poly1305_decrypt pogost_chacha20poly1305_decrypt
#define xchacha20poly1305_encrypt pogost_xchacha20poly1305_encrypt
#define xchacha20poly1305_decrypt pogost_xchacha20poly1305_decrypt

#define CURVE25519_KEY_SIZE POGOST_CURVE25519_KEY_SIZE
#define curve25519_generic pogost_curve25519_generic
#define curve25519 pogost_curve25519
#define curve25519_generate_public pogost_curve25519_generate_public
#define curve25519_clamp_secret pogost_curve25519_clamp_secret

#undef CONFIG_CRYPTO_LIB_BLAKE2S_ARCH
#undef CONFIG_CRYPTO_LIB_CHACHA_ARCH
#undef CONFIG_CRYPTO_LIB_CURVE25519_ARCH
#undef CONFIG_CRYPTO_LIB_POLY1305_ARCH

#endif
