/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-2-Clause */
#ifndef LIBPOGOST_STREEBOG_H
#define LIBPOGOST_STREEBOG_H

#include <stddef.h>
#include <stdint.h>

#define STREEBOG256_DIGEST_SIZE 32
#define STREEBOG512_DIGEST_SIZE 64
#define STREEBOG_BLOCK_SIZE 64
#define STREEBOG_CTX_SIZE 336

struct streebog_ctx {
  uint64_t opaque[STREEBOG_CTX_SIZE / sizeof(uint64_t)];
};

void streebog_init(struct streebog_ctx *ctx, unsigned int bits);
void streebog_update(struct streebog_ctx *ctx, const uint8_t *data, size_t len);
void streebog_final(struct streebog_ctx *ctx, uint8_t *digest);
void streebog256(uint8_t digest[STREEBOG256_DIGEST_SIZE],
                 const uint8_t *data, size_t len);
void streebog512(uint8_t digest[STREEBOG512_DIGEST_SIZE],
                 const uint8_t *data, size_t len);

#endif
