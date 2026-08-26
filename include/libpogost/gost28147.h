/* SPDX-License-Identifier: MIT */
#ifndef LIBPOGOST_GOST28147_H
#include <libpogost/types.h>

#define LIBPOGOST_GOST28147_H


#define GOST28147_KEY_SIZE 32
#define GOST28147_BLOCK_SIZE 8
#define GOST28147_CTX_SIZE 40

struct gost28147_ctx {
  u64 opaque[GOST28147_CTX_SIZE / sizeof(u64)];
};

int gost28147_setkey_cryptopro_a(struct gost28147_ctx *ctx,
                                 const u8 key[GOST28147_KEY_SIZE]);
void gost28147_encrypt(const struct gost28147_ctx *ctx,
                       u8 out[GOST28147_BLOCK_SIZE],
                       const u8 in[GOST28147_BLOCK_SIZE]);
void gost28147_decrypt(const struct gost28147_ctx *ctx,
                       u8 out[GOST28147_BLOCK_SIZE],
                       const u8 in[GOST28147_BLOCK_SIZE]);

#endif
