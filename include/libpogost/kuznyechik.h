/* Публичный API блочного шифра Kuznyechik. */
#ifndef LIBPOGOST_KUZNYECHIK_H
#include <libpogost/types.h>

#define LIBPOGOST_KUZNYECHIK_H


#define KUZNYECHIK_KEY_SIZE 32
#define KUZNYECHIK_BLOCK_SIZE 16
#define KUZNYECHIK_CTX_SIZE 320

struct kuznyechik_ctx {
  u8 opaque[KUZNYECHIK_CTX_SIZE];
};

int kuznyechik_setkey(struct kuznyechik_ctx *ctx,
                     const u8 key[KUZNYECHIK_KEY_SIZE]);
void kuznyechik_encrypt(const struct kuznyechik_ctx *ctx,
                       u8 out[KUZNYECHIK_BLOCK_SIZE],
                       const u8 in[KUZNYECHIK_BLOCK_SIZE]);
void kuznyechik_decrypt(const struct kuznyechik_ctx *ctx,
                       u8 out[KUZNYECHIK_BLOCK_SIZE],
                       const u8 in[KUZNYECHIK_BLOCK_SIZE]);

#endif
