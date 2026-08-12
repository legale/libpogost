/* Публичный API блочного шифра Kuznechik. */
#ifndef LIBPOGOST_KUZNECHIK_H
#define LIBPOGOST_KUZNECHIK_H

#include <stdint.h>

#define KUZNECHIK_KEY_SIZE 32
#define KUZNECHIK_BLOCK_SIZE 16
#define KUZNECHIK_CTX_SIZE 320

struct kuznechik_ctx {
  uint8_t opaque[KUZNECHIK_CTX_SIZE];
};

int kuznechik_setkey(struct kuznechik_ctx *ctx,
                     const uint8_t key[KUZNECHIK_KEY_SIZE]);
void kuznechik_encrypt(const struct kuznechik_ctx *ctx,
                       uint8_t out[KUZNECHIK_BLOCK_SIZE],
                       const uint8_t in[KUZNECHIK_BLOCK_SIZE]);
void kuznechik_decrypt(const struct kuznechik_ctx *ctx,
                       uint8_t out[KUZNECHIK_BLOCK_SIZE],
                       const uint8_t in[KUZNECHIK_BLOCK_SIZE]);

#endif
