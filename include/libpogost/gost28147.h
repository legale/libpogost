/* SPDX-License-Identifier: MIT */
#ifndef LIBPOGOST_GOST28147_H
#define LIBPOGOST_GOST28147_H

#include <stdint.h>

#define GOST28147_KEY_SIZE 32
#define GOST28147_BLOCK_SIZE 8
#define GOST28147_CTX_SIZE 40

struct gost28147_ctx {
  uint64_t opaque[GOST28147_CTX_SIZE / sizeof(uint64_t)];
};

int gost28147_setkey_cryptopro_a(struct gost28147_ctx *ctx,
                                 const uint8_t key[GOST28147_KEY_SIZE]);
void gost28147_encrypt(const struct gost28147_ctx *ctx,
                       uint8_t out[GOST28147_BLOCK_SIZE],
                       const uint8_t in[GOST28147_BLOCK_SIZE]);
void gost28147_decrypt(const struct gost28147_ctx *ctx,
                       uint8_t out[GOST28147_BLOCK_SIZE],
                       const uint8_t in[GOST28147_BLOCK_SIZE]);

#endif
