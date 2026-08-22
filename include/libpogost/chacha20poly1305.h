/* SPDX-License-Identifier: GPL-2.0 OR MIT */
#ifndef LIBPOGOST_CHACHA20POLY1305_H
#define LIBPOGOST_CHACHA20POLY1305_H

#include <libpogost/types.h>

#define POGOST_XCHACHA20POLY1305_NONCE_SIZE 24
#define POGOST_CHACHA20POLY1305_KEY_SIZE 32
#define POGOST_CHACHA20POLY1305_AUTHTAG_SIZE 16

void pogost_chacha20poly1305_encrypt(u8 *dst, const u8 *src, size_t src_len,
				     const u8 *ad, size_t ad_len, u64 nonce,
				     const u8 key[32]);
bool pogost_chacha20poly1305_decrypt(u8 *dst, const u8 *src, size_t src_len,
				     const u8 *ad, size_t ad_len, u64 nonce,
				     const u8 key[32]);
void pogost_xchacha20poly1305_encrypt(u8 *dst, const u8 *src, size_t src_len,
				      const u8 *ad, size_t ad_len,
				      const u8 nonce[24], const u8 key[32]);
bool pogost_xchacha20poly1305_decrypt(u8 *dst, const u8 *src, size_t src_len,
				      const u8 *ad, size_t ad_len,
				      const u8 nonce[24], const u8 key[32]);

#endif
