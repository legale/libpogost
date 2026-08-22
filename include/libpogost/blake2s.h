/* SPDX-License-Identifier: GPL-2.0 OR MIT */
#ifndef LIBPOGOST_BLAKE2S_H
#define LIBPOGOST_BLAKE2S_H

#include <libpogost/types.h>

enum pogost_blake2s_lengths {
	POGOST_BLAKE2S_BLOCK_SIZE = 64,
	POGOST_BLAKE2S_HASH_SIZE = 32,
	POGOST_BLAKE2S_KEY_SIZE = 32,
};

enum pogost_blake2s_iv {
	POGOST_BLAKE2S_IV0 = 0x6A09E667UL,
	POGOST_BLAKE2S_IV1 = 0xBB67AE85UL,
	POGOST_BLAKE2S_IV2 = 0x3C6EF372UL,
	POGOST_BLAKE2S_IV3 = 0xA54FF53AUL,
	POGOST_BLAKE2S_IV4 = 0x510E527FUL,
	POGOST_BLAKE2S_IV5 = 0x9B05688CUL,
	POGOST_BLAKE2S_IV6 = 0x1F83D9ABUL,
	POGOST_BLAKE2S_IV7 = 0x5BE0CD19UL,
};

struct pogost_blake2s_ctx {
	u32 h[8];
	u32 t[2];
	u32 f[2];
	u8 buf[POGOST_BLAKE2S_BLOCK_SIZE];
	unsigned int buflen;
	unsigned int outlen;
};

void pogost_blake2s_init(struct pogost_blake2s_ctx *ctx, size_t outlen);
void pogost_blake2s_init_key(struct pogost_blake2s_ctx *ctx, size_t outlen,
			      const void *key, size_t keylen);
void pogost_blake2s_update(struct pogost_blake2s_ctx *ctx, const u8 *in,
			    size_t inlen);
void pogost_blake2s_final(struct pogost_blake2s_ctx *ctx, u8 *out);
void pogost_blake2s(const u8 *key, size_t keylen, const u8 *in, size_t inlen,
		    u8 *out, size_t outlen);

#endif
