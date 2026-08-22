// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This is an implementation of the ChaCha20Poly1305 AEAD construction.
 *
 * Information: https://tools.ietf.org/html/rfc8439
 */

#include "../kernel_compat.h"
#include "../poly1305_internal.h"

static void chacha_load_key(u32 *k, const u8 *in)
{
	k[0] = get_unaligned_le32(in);
	k[1] = get_unaligned_le32(in + 4);
	k[2] = get_unaligned_le32(in + 8);
	k[3] = get_unaligned_le32(in + 12);
	k[4] = get_unaligned_le32(in + 16);
	k[5] = get_unaligned_le32(in + 20);
	k[6] = get_unaligned_le32(in + 24);
	k[7] = get_unaligned_le32(in + 28);
}

static void xchacha_init(struct chacha_state *chacha_state,
			 const u8 *key, const u8 *nonce)
{
	u32 k[CHACHA_KEY_WORDS];
	u8 iv[CHACHA_IV_SIZE];

	memset(iv, 0, 8);
	memcpy(iv + 8, nonce + 16, 8);

	chacha_load_key(k, key);

	/* Compute the subkey given the original key and first 128 nonce bits */
	chacha_init(chacha_state, k, nonce);
	hchacha_block(chacha_state, k, 20);

	chacha_init(chacha_state, k, iv);

	memzero_explicit(k, sizeof(k));
	memzero_explicit(iv, sizeof(iv));
}

static void
__chacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
			   const u8 *ad, const size_t ad_len,
			   struct chacha_state *chacha_state)
{
	const u8 *pad0 = page_address(ZERO_PAGE(0));
	struct poly1305_desc_ctx poly1305_state;
	union {
		u8 block0[POLY1305_KEY_SIZE];
		__le64 lens[2];
	} b;

	chacha20_crypt(chacha_state, b.block0, pad0, sizeof(b.block0));
	poly1305_init(&poly1305_state, b.block0);

	poly1305_update(&poly1305_state, ad, ad_len);
	if (ad_len & 0xf)
		poly1305_update(&poly1305_state, pad0, 0x10 - (ad_len & 0xf));

	chacha20_crypt(chacha_state, dst, src, src_len);

	poly1305_update(&poly1305_state, dst, src_len);
	if (src_len & 0xf)
		poly1305_update(&poly1305_state, pad0, 0x10 - (src_len & 0xf));

	b.lens[0] = cpu_to_le64(ad_len);
	b.lens[1] = cpu_to_le64(src_len);
	poly1305_update(&poly1305_state, (u8 *)b.lens, sizeof(b.lens));

	poly1305_final(&poly1305_state, dst + src_len);

	chacha_zeroize_state(chacha_state);
	memzero_explicit(&b, sizeof(b));
}

void chacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
			      const u8 *ad, const size_t ad_len,
			      const u64 nonce,
			      const u8 key[at_least CHACHA20POLY1305_KEY_SIZE])
{
	struct chacha_state chacha_state;
	u32 k[CHACHA_KEY_WORDS];
	__le64 iv[2];

	chacha_load_key(k, key);

	iv[0] = 0;
	iv[1] = cpu_to_le64(nonce);

	chacha_init(&chacha_state, k, (u8 *)iv);
	__chacha20poly1305_encrypt(dst, src, src_len, ad, ad_len,
				   &chacha_state);

	memzero_explicit(iv, sizeof(iv));
	memzero_explicit(k, sizeof(k));
}

void xchacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
			       const u8 *ad, const size_t ad_len,
			       const u8 nonce[at_least XCHACHA20POLY1305_NONCE_SIZE],
			       const u8 key[at_least CHACHA20POLY1305_KEY_SIZE])
{
	struct chacha_state chacha_state;

	xchacha_init(&chacha_state, key, nonce);
	__chacha20poly1305_encrypt(dst, src, src_len, ad, ad_len,
				   &chacha_state);
}

static bool
__chacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
			   const u8 *ad, const size_t ad_len,
			   struct chacha_state *chacha_state)
{
	const u8 *pad0 = page_address(ZERO_PAGE(0));
	struct poly1305_desc_ctx poly1305_state;
	size_t dst_len;
	int ret;
	union {
		u8 block0[POLY1305_KEY_SIZE];
		u8 mac[POLY1305_DIGEST_SIZE];
		__le64 lens[2];
	} b;

	if (unlikely(src_len < POLY1305_DIGEST_SIZE))
		return false;

	chacha20_crypt(chacha_state, b.block0, pad0, sizeof(b.block0));
	poly1305_init(&poly1305_state, b.block0);

	poly1305_update(&poly1305_state, ad, ad_len);
	if (ad_len & 0xf)
		poly1305_update(&poly1305_state, pad0, 0x10 - (ad_len & 0xf));

	dst_len = src_len - POLY1305_DIGEST_SIZE;
	poly1305_update(&poly1305_state, src, dst_len);
	if (dst_len & 0xf)
		poly1305_update(&poly1305_state, pad0, 0x10 - (dst_len & 0xf));

	b.lens[0] = cpu_to_le64(ad_len);
	b.lens[1] = cpu_to_le64(dst_len);
	poly1305_update(&poly1305_state, (u8 *)b.lens, sizeof(b.lens));

	poly1305_final(&poly1305_state, b.mac);

	ret = crypto_memneq(b.mac, src + dst_len, POLY1305_DIGEST_SIZE);
	if (likely(!ret))
		chacha20_crypt(chacha_state, dst, src, dst_len);

	memzero_explicit(&b, sizeof(b));

	return !ret;
}

bool chacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
			      const u8 *ad, const size_t ad_len,
			      const u64 nonce,
			      const u8 key[at_least CHACHA20POLY1305_KEY_SIZE])
{
	struct chacha_state chacha_state;
	u32 k[CHACHA_KEY_WORDS];
	__le64 iv[2];
	bool ret;

	chacha_load_key(k, key);

	iv[0] = 0;
	iv[1] = cpu_to_le64(nonce);

	chacha_init(&chacha_state, k, (u8 *)iv);
	ret = __chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len,
					 &chacha_state);

	chacha_zeroize_state(&chacha_state);
	memzero_explicit(iv, sizeof(iv));
	memzero_explicit(k, sizeof(k));
	return ret;
}

bool xchacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
			       const u8 *ad, const size_t ad_len,
			       const u8 nonce[at_least XCHACHA20POLY1305_NONCE_SIZE],
			       const u8 key[at_least CHACHA20POLY1305_KEY_SIZE])
{
	struct chacha_state chacha_state;

	xchacha_init(&chacha_state, key, nonce);
	return __chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len,
					  &chacha_state);
}
