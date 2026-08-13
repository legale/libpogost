/* Публичный API блочного шифра Kuznyechik. */
#ifndef LIBPOGOST_KUZNYECHIK_H
#define LIBPOGOST_KUZNYECHIK_H

#include <stdint.h>

#define KUZNYECHIK_KEY_SIZE 32
#define KUZNYECHIK_BLOCK_SIZE 16
#define KUZNYECHIK_CTX_SIZE 320

struct kuznyechik_ctx {
  uint8_t opaque[KUZNYECHIK_CTX_SIZE];
};

int kuznyechik_setkey(struct kuznyechik_ctx *ctx,
                     const uint8_t key[KUZNYECHIK_KEY_SIZE]);
void kuznyechik_encrypt(const struct kuznyechik_ctx *ctx,
                       uint8_t out[KUZNYECHIK_BLOCK_SIZE],
                       const uint8_t in[KUZNYECHIK_BLOCK_SIZE]);
void kuznyechik_decrypt(const struct kuznyechik_ctx *ctx,
                       uint8_t out[KUZNYECHIK_BLOCK_SIZE],
                       const uint8_t in[KUZNYECHIK_BLOCK_SIZE]);

#endif
