#include <libpogost/kuznechik.h>

#include "kuznechik_internal.h"

/* Пока выбран только проверенный generic backend. */
int kuznechik_setkey(struct kuznechik_ctx *ctx,
                     const uint8_t key[KUZNECHIK_KEY_SIZE])
{
  return kuznechik_generic_setkey(ctx, key);
}

void kuznechik_encrypt(const struct kuznechik_ctx *ctx,
                       uint8_t out[KUZNECHIK_BLOCK_SIZE],
                       const uint8_t in[KUZNECHIK_BLOCK_SIZE])
{
  kuznechik_generic_encrypt(ctx, out, in);
}

void kuznechik_decrypt(const struct kuznechik_ctx *ctx,
                       uint8_t out[KUZNECHIK_BLOCK_SIZE],
                       const uint8_t in[KUZNECHIK_BLOCK_SIZE])
{
  kuznechik_generic_decrypt(ctx, out, in);
}
