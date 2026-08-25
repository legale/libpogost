/* SPDX-License-Identifier: OpenSSL */
#include "gost28147_internal.h"
#include "gost3411_94_internal.h"

#include <string.h>

struct gost3411_94_ctx {
  struct gost28147_state cipher;
  uint64_t len;
  size_t left;
  uint8_t h[32];
  uint8_t sum[32];
  uint8_t rem[32];
};

static void swap_bytes(const uint8_t *w, uint8_t *key)
{
  unsigned int i;
  unsigned int j;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < 8; j++) {
      key[i + 4 * j] = w[8 * i + j];
    }
  }
}

static void circle_xor8(const uint8_t *w, uint8_t *k)
{
  uint8_t buf[8];
  unsigned int i;

  memcpy(buf, w, sizeof(buf));
  memmove(k, w + 8, 24);
  for (i = 0; i < 8; i++) {
    k[i + 24] = buf[i] ^ k[i];
  }
}

static void transform_3(uint8_t data[32])
{
  uint16_t acc;

  acc = data[0] ^ data[2] ^ data[4] ^ data[6] ^ data[24] ^ data[30];
  acc |= (uint16_t)(data[1] ^ data[3] ^ data[5] ^ data[7] ^ data[25] ^
                    data[31]) << 8;
  memmove(data, data + 2, 30);
  data[30] = acc;
  data[31] = acc >> 8;
}

static void add_blocks(uint8_t left[32], const uint8_t right[32])
{
  unsigned int carry = 0;
  unsigned int i;

  for (i = 0; i < 32; i++) {
    unsigned int sum = left[i] + right[i] + carry;

    left[i] = sum;
    carry = sum >> 8;
  }
}

static void xor_blocks(uint8_t out[32], const uint8_t a[32],
                       const uint8_t b[32])
{
  unsigned int i;

  for (i = 0; i < 32; i++) {
    out[i] = a[i] ^ b[i];
  }
}

static void encrypt_key(struct gost28147_state *st, const uint8_t key[32],
                        const uint8_t in[8], uint8_t out[8])
{
  gost28147_setkey_raw(st, key, gost28147_sbox_cryptopro_3411);
  gost28147_encrypt_raw(st, out, in);
}

static void hash_step(struct gost3411_94_ctx *ctx, uint8_t h[32],
                      const uint8_t m[32])
{
  uint8_t u[32];
  uint8_t v[32];
  uint8_t w[32];
  uint8_t s[32];
  uint8_t key[32];
  unsigned int i;

  xor_blocks(w, h, m);
  swap_bytes(w, key);
  encrypt_key(&ctx->cipher, key, h, s);

  circle_xor8(h, u);
  circle_xor8(m, v);
  circle_xor8(v, v);
  xor_blocks(w, u, v);
  swap_bytes(w, key);
  encrypt_key(&ctx->cipher, key, h + 8, s + 8);

  circle_xor8(u, u);
  u[31] = ~u[31];
  u[29] = ~u[29];
  u[28] = ~u[28];
  u[24] = ~u[24];
  u[23] = ~u[23];
  u[20] = ~u[20];
  u[18] = ~u[18];
  u[17] = ~u[17];
  u[14] = ~u[14];
  u[12] = ~u[12];
  u[10] = ~u[10];
  u[8] = ~u[8];
  u[7] = ~u[7];
  u[5] = ~u[5];
  u[3] = ~u[3];
  u[1] = ~u[1];
  circle_xor8(v, v);
  circle_xor8(v, v);
  xor_blocks(w, u, v);
  swap_bytes(w, key);
  encrypt_key(&ctx->cipher, key, h + 16, s + 16);

  circle_xor8(u, u);
  circle_xor8(v, v);
  circle_xor8(v, v);
  xor_blocks(w, u, v);
  swap_bytes(w, key);
  encrypt_key(&ctx->cipher, key, h + 24, s + 24);

  for (i = 0; i < 12; i++) {
    transform_3(s);
  }
  xor_blocks(s, s, m);
  transform_3(s);
  xor_blocks(s, s, h);
  for (i = 0; i < 61; i++) {
    transform_3(s);
  }
  memcpy(h, s, 32);
}

static void update(struct gost3411_94_ctx *ctx, const uint8_t *data, size_t len)
{
  if (ctx->left) {
    size_t n = 32 - ctx->left;

    if (n > len) {
      n = len;
    }
    memcpy(ctx->rem + ctx->left, data, n);
    ctx->left += n;
    if (ctx->left < 32) {
      return;
    }
    data += n;
    len -= n;
    hash_step(ctx, ctx->h, ctx->rem);
    add_blocks(ctx->sum, ctx->rem);
    ctx->len += 32;
    ctx->left = 0;
  }

  while (len >= 32) {
    hash_step(ctx, ctx->h, data);
    add_blocks(ctx->sum, data);
    ctx->len += 32;
    data += 32;
    len -= 32;
  }
  if (len) {
    memcpy(ctx->rem, data, len);
    ctx->left = len;
  }
}

static void final(struct gost3411_94_ctx *ctx, uint8_t out[32])
{
  uint8_t buf[32] = { 0 };
  uint8_t h[32];
  uint8_t sum[32];
  uint64_t len = ctx->len;
  unsigned int i;

  memcpy(h, ctx->h, sizeof(h));
  memcpy(sum, ctx->sum, sizeof(sum));
  if (ctx->left) {
    memcpy(buf, ctx->rem, ctx->left);
    hash_step(ctx, h, buf);
    add_blocks(sum, buf);
    len += ctx->left;
  }
  memset(buf, 0, sizeof(buf));
  if (!len) {
    hash_step(ctx, h, buf);
  }
  len <<= 3;
  for (i = 0; len && i < sizeof(buf); i++) {
    buf[i] = len;
    len >>= 8;
  }
  hash_step(ctx, h, buf);
  hash_step(ctx, h, sum);
  memcpy(out, h, 32);
}

void gost3411_94_cryptopro_parts(uint8_t out[32],
                                 const uint8_t *a, size_t a_len,
                                 const uint8_t *b, size_t b_len,
                                 const uint8_t *c, size_t c_len)
{
  struct gost3411_94_ctx ctx;

  memset(&ctx, 0, sizeof(ctx));
  ctx.cipher.sbox = gost28147_sbox_cryptopro_3411;
  if (a_len) {
    update(&ctx, a, a_len);
  }
  if (b_len) {
    update(&ctx, b, b_len);
  }
  if (c_len) {
    update(&ctx, c, c_len);
  }
  final(&ctx, out);
  memset(&ctx, 0, sizeof(ctx));
}

void gost3411_94_cryptopro(uint8_t out[32], const uint8_t *data, size_t len)
{
  gost3411_94_cryptopro_parts(out, data, len, NULL, 0, NULL, 0);
}
