/* SPDX-License-Identifier: GPL-2.0 OR MIT */
#include "../kernel_compat.h"


static void blake2s_init_(struct blake2s_ctx *ctx, size_t outlen,
			 const void *key, size_t keylen)
{
	ctx->h[0] = BLAKE2S_IV0 ^ (0x01010000 | keylen << 8 | outlen);
	ctx->h[1] = BLAKE2S_IV1; ctx->h[2] = BLAKE2S_IV2;
	ctx->h[3] = BLAKE2S_IV3; ctx->h[4] = BLAKE2S_IV4;
	ctx->h[5] = BLAKE2S_IV5; ctx->h[6] = BLAKE2S_IV6;
	ctx->h[7] = BLAKE2S_IV7;
	ctx->t[0] = ctx->t[1] = ctx->f[0] = ctx->f[1] = 0;
	ctx->buflen = 0;
	ctx->outlen = outlen;
	if (keylen) {
		memcpy(ctx->buf, key, keylen);
		memset(&ctx->buf[keylen], 0, BLAKE2S_BLOCK_SIZE - keylen);
		ctx->buflen = BLAKE2S_BLOCK_SIZE;
	}
}

void pogost_blake2s_init(struct pogost_blake2s_ctx *ctx, size_t outlen)
{
	blake2s_init_(ctx, outlen, NULL, 0);
}

void pogost_blake2s_init_key(struct pogost_blake2s_ctx *ctx, size_t outlen,
			      const void *key, size_t keylen)
{
	blake2s_init_(ctx, outlen, key, keylen);
}

void pogost_blake2s(const u8 *key, size_t keylen, const u8 *in, size_t inlen,
		    u8 *out, size_t outlen)
{
	struct pogost_blake2s_ctx ctx;
	blake2s_init_(&ctx, outlen, key, keylen);
	pogost_blake2s_update(&ctx, in, inlen);
	pogost_blake2s_final(&ctx, out);
}
