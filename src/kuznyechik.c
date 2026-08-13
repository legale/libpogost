#include <libpogost/kuznyechik.h>

#include "kuznyechik_internal.h"

/* Пока выбран только проверенный generic backend. */
int kuznyechik_setkey(struct kuznyechik_ctx *ctx,
                     const uint8_t key[KUZNYECHIK_KEY_SIZE])
{
  return kuznyechik_generic_setkey(ctx, key);
}

void kuznyechik_encrypt(const struct kuznyechik_ctx *ctx,
                       uint8_t out[KUZNYECHIK_BLOCK_SIZE],
                       const uint8_t in[KUZNYECHIK_BLOCK_SIZE])
{
  kuznyechik_generic_encrypt(ctx, out, in);
}

void kuznyechik_decrypt(const struct kuznyechik_ctx *ctx,
                       uint8_t out[KUZNYECHIK_BLOCK_SIZE],
                       const uint8_t in[KUZNYECHIK_BLOCK_SIZE])
{
  kuznyechik_generic_decrypt(ctx, out, in);
}
