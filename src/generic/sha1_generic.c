/* SPDX-License-Identifier: Apache-2.0 */
#include "sha1_internal.h"

#include <string.h>

static u32 rol32(u32 value, unsigned int shift)
{
  return (value << shift) | (value >> (32 - shift));
}

static void sha1_block(struct sha1_ctx *ctx, const u8 block[64])
{
  u32 w[80];
  u32 a, b, c, d, e, f, k, t;
  unsigned int i;

  for (i = 0; i < 16; i++)
    w[i] = ((u32)block[i * 4] << 24) | ((u32)block[i * 4 + 1] << 16) |
           ((u32)block[i * 4 + 2] << 8) | block[i * 4 + 3];
  for (; i < 80; i++)
    w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  a = ctx->h[0];
  b = ctx->h[1];
  c = ctx->h[2];
  d = ctx->h[3];
  e = ctx->h[4];
  for (i = 0; i < 80; i++) {
    if (i < 20) {
      f = (b & c) | (~b & d);
      k = 0x5a827999;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ed9eba1;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8f1bbcdc;
    } else {
      f = b ^ c ^ d;
      k = 0xca62c1d6;
    }
    t = rol32(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = rol32(b, 30);
    b = a;
    a = t;
  }
  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
  ctx->h[4] += e;
}

void sha1_init(struct sha1_ctx *ctx)
{
  ctx->h[0] = 0x67452301;
  ctx->h[1] = 0xefcdab89;
  ctx->h[2] = 0x98badcfe;
  ctx->h[3] = 0x10325476;
  ctx->h[4] = 0xc3d2e1f0;
  ctx->bits = 0;
  ctx->used = 0;
}

void sha1_update(struct sha1_ctx *ctx, const u8 *data, size_t len)
{
  size_t take;

  ctx->bits += (u64)len * 8;
  while (len) {
    take = 64 - ctx->used;
    if (take > len)
      take = len;
    memcpy(ctx->block + ctx->used, data, take);
    ctx->used += take;
    data += take;
    len -= take;
    if (ctx->used == 64) {
      sha1_block(ctx, ctx->block);
      ctx->used = 0;
    }
  }
}

void sha1_final(struct sha1_ctx *ctx, u8 out[20])
{
  u64 bits = ctx->bits;
  unsigned int i;

  ctx->block[ctx->used++] = 0x80;
  if (ctx->used > 56) {
    memset(ctx->block + ctx->used, 0, 64 - ctx->used);
    sha1_block(ctx, ctx->block);
    ctx->used = 0;
  }
  memset(ctx->block + ctx->used, 0, 56 - ctx->used);
  for (i = 0; i < 8; i++)
    ctx->block[56 + i] = (u8)(bits >> (56 - i * 8));
  sha1_block(ctx, ctx->block);
  for (i = 0; i < 5; i++) {
    out[i * 4] = (u8)(ctx->h[i] >> 24);
    out[i * 4 + 1] = (u8)(ctx->h[i] >> 16);
    out[i * 4 + 2] = (u8)(ctx->h[i] >> 8);
    out[i * 4 + 3] = (u8)ctx->h[i];
  }
}
