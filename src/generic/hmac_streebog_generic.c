/* SPDX-License-Identifier: Apache-2.0 */
#include <libpogost/streebog.h>

#include "hmac_streebog_internal.h"

#include <string.h>

static void memzero(void *ptr, size_t len)
{
  volatile u8 *p = ptr;

  while (len--) {
    *p++ = 0;
  }
}

static void hmac_parts(u8 *out, unsigned int bits,
                       const u8 *key, size_t key_len,
                       const u8 *a, size_t a_len,
                       const u8 *b, size_t b_len,
                       const u8 *c, size_t c_len)
{
  struct streebog_ctx ctx;
  u8 key_block[STREEBOG_BLOCK_SIZE] = { 0 };
  u8 inner[STREEBOG512_DIGEST_SIZE];
  u8 pad[STREEBOG_BLOCK_SIZE];
  size_t digest_len = bits == 256 ? STREEBOG256_DIGEST_SIZE :
                                    STREEBOG512_DIGEST_SIZE;
  size_t i;

  if (key_len > sizeof(key_block)) {
    if (bits == 256) {
      streebog256(key_block, key, key_len);
    } else {
      streebog512(key_block, key, key_len);
    }
  } else if (key_len) {
    memcpy(key_block, key, key_len);
  }

  for (i = 0; i < sizeof(pad); i++) {
    pad[i] = key_block[i] ^ 0x36;
  }
  streebog_init(&ctx, bits);
  streebog_update(&ctx, pad, sizeof(pad));
  if (a_len) {
    streebog_update(&ctx, a, a_len);
  }
  if (b_len) {
    streebog_update(&ctx, b, b_len);
  }
  if (c_len) {
    streebog_update(&ctx, c, c_len);
  }
  streebog_final(&ctx, inner);

  for (i = 0; i < sizeof(pad); i++) {
    pad[i] = key_block[i] ^ 0x5c;
  }
  streebog_init(&ctx, bits);
  streebog_update(&ctx, pad, sizeof(pad));
  streebog_update(&ctx, inner, digest_len);
  streebog_final(&ctx, out);

  memzero(key_block, sizeof(key_block));
  memzero(inner, sizeof(inner));
  memzero(pad, sizeof(pad));
  memzero(&ctx, sizeof(ctx));
}

void hmac_streebog256(u8 out[32], const u8 *key, size_t key_len,
                      const u8 *data, size_t data_len)
{
  hmac_parts(out, 256, key, key_len, data, data_len, NULL, 0, NULL, 0);
}

void hmac_streebog512(u8 out[64], const u8 *key, size_t key_len,
                      const u8 *data, size_t data_len)
{
  hmac_parts(out, 512, key, key_len, data, data_len, NULL, 0, NULL, 0);
}

void hmac_streebog256_parts(u8 out[32], const u8 *key, size_t key_len,
                            const u8 *a, size_t a_len,
                            const u8 *b, size_t b_len,
                            const u8 *c, size_t c_len)
{
  hmac_parts(out, 256, key, key_len, a, a_len, b, b_len, c, c_len);
}

void hmac_streebog512_parts(u8 out[64], const u8 *key, size_t key_len,
                            const u8 *a, size_t a_len,
                            const u8 *b, size_t b_len)
{
  hmac_parts(out, 512, key, key_len, a, a_len, b, b_len, NULL, 0);
}
