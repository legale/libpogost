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

extern const u8 gost28147_sbox_cryptopro_a[8][16];
extern const u8 gost28147_sbox_tc26_z[8][16];

/*
 * Имит-подобный MAC из gost-engine/gost_crypt.c:
 * 16 раундов GOST 28147, ключевые слова = a[i] - b[i].
 * Начальное состояние и неполный последний блок обрабатываются так же,
 * как в наблюдавшемся update libcsp для CPExportBlob2.
 */
int gost28147_imit_cp12_sbox(u8 out[4], const u8 *in, size_t len,
                             const u8 initial_state[GOST28147_BLOCK_SIZE],
                             const u8 a[GOST28147_KEY_SIZE],
                             const u8 b[GOST28147_KEY_SIZE],
                             const u8 sbox[8][16]);

int gost28147_imit_cp12(u8 out[4], const u8 *in, size_t len,
                        const u8 initial_state[GOST28147_BLOCK_SIZE],
                        const u8 a[GOST28147_KEY_SIZE],
                        const u8 b[GOST28147_KEY_SIZE]);

#endif
