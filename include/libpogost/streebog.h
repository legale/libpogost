/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-2-Clause */
#ifndef LIBPOGOST_STREEBOG_H
#define LIBPOGOST_STREEBOG_H

#include <libpogost/types.h>

#define STREEBOG256_DIGEST_SIZE 32
#define STREEBOG512_DIGEST_SIZE 64
#define STREEBOG_BLOCK_SIZE 64
#define STREEBOG_CTX_SIZE 336

struct streebog_ctx {
  u64 opaque[STREEBOG_CTX_SIZE / sizeof(u64)];
};

void streebog_init(struct streebog_ctx *ctx, unsigned int bits);
void streebog_update(struct streebog_ctx *ctx, const u8 *data, size_t len);
void streebog_final(struct streebog_ctx *ctx, u8 *digest);
void streebog256(u8 digest[STREEBOG256_DIGEST_SIZE],
                 const u8 *data, size_t len);
void streebog512(u8 digest[STREEBOG512_DIGEST_SIZE],
                 const u8 *data, size_t len);

#endif
