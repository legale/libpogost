/* SPDX-License-Identifier: Apache-2.0 */
#include <libpogost/gost_tls.h>
#include <libpogost/kuznyechik.h>
#include <libpogost/streebog.h>

#include "hmac_streebog_internal.h"

#include <stdlib.h>
#include <string.h>

static void memzero(void *ptr, size_t len)
{
  volatile u8 *p = ptr;

  while (len--)
    *p++ = 0;
}

void gost_hmac_streebog256(u8 out[32], const u8 *key, size_t key_len,
                           const u8 *data, size_t data_len)
{
  hmac_streebog256(out, key, key_len, data, data_len);
}

static size_t put_be(u8 out[sizeof(size_t)], size_t value)
{
  size_t pos = sizeof(size_t);

  do {
    out[--pos] = value & 0xff;
    value >>= 8;
  } while (value);
  memmove(out, out + pos, sizeof(size_t) - pos);
  return sizeof(size_t) - pos;
}

int gost_kdf_tree_256(u8 *out, size_t out_len,
                      const u8 *key, size_t key_len,
                      const u8 *label, size_t label_len,
                      const u8 *seed, size_t seed_len)
{
  u8 suffix[1 + 255 + sizeof(size_t)];
  u8 len_buf[sizeof(size_t)];
  u8 counter;
  size_t len_len;
  size_t off;

  if (!out_len || out_len % 32 || out_len / 32 > 255 || seed_len > 255)
    return -1;

  len_len = put_be(len_buf, out_len * 8);
  suffix[0] = 0;
  memcpy(suffix + 1, seed, seed_len);
  memcpy(suffix + 1 + seed_len, len_buf, len_len);

  for (off = 0, counter = 1; off < out_len; off += 32, counter++)
    hmac_streebog256_parts(out + off, key, key_len, &counter, 1,
                           label, label_len, suffix,
                           1 + seed_len + len_len);

  memzero(suffix, sizeof(suffix));
  return 0;
}

int gost_tls_prf_256(u8 *out, size_t out_len,
                     const u8 *secret, size_t secret_len,
                     const char *label, const u8 *seed, size_t seed_len)
{
  u8 a[32];
  u8 block[32];
  size_t label_len = strlen(label);
  size_t take;

  hmac_streebog256_parts(a, secret, secret_len,
                         (const u8 *)label, label_len,
                         seed, seed_len, NULL, 0);
  while (out_len) {
    hmac_streebog256_parts(block, secret, secret_len, a, sizeof(a),
                           (const u8 *)label, label_len,
                           seed, seed_len);
    take = out_len < sizeof(block) ? out_len : sizeof(block);
    memcpy(out, block, take);
    out += take;
    out_len -= take;
    hmac_streebog256(a, secret, secret_len, a, sizeof(a));
  }

  memzero(a, sizeof(a));
  memzero(block, sizeof(block));
  return 0;
}

static u64 get_le64(const u8 in[8])
{
  u64 value = 0;
  unsigned int i;

  for (i = 0; i < 8; i++)
    value |= (u64)in[i] << (8 * i);
  return value;
}

static void put_le64(u8 out[8], u64 value)
{
  unsigned int i;

  for (i = 0; i < 8; i++)
    out[i] = value >> (8 * i);
}

int gost_tls_tlstree_kuznyechik(u8 out[32], const u8 key[32],
                                const u8 seq[8])
{
  static const u8 level1[] = "level1";
  static const u8 level2[] = "level2";
  static const u8 level3[] = "level3";
  u8 seed[8];
  u8 tmp1[32];
  u8 tmp2[32];
  u64 n = get_le64(seq);
  int ret = -1;

  put_le64(seed, n & UINT64_C(0x00000000ffffffff));
  if (gost_kdf_tree_256(tmp1, sizeof(tmp1), key, 32,
                        level1, sizeof(level1) - 1, seed, sizeof(seed)))
    goto out;
  put_le64(seed, n & UINT64_C(0x0000f8ffffffffff));
  if (gost_kdf_tree_256(tmp2, sizeof(tmp2), tmp1, sizeof(tmp1),
                        level2, sizeof(level2) - 1, seed, sizeof(seed)))
    goto out;
  put_le64(seed, n & UINT64_C(0xc0ffffffffffffff));
  if (gost_kdf_tree_256(out, 32, tmp2, sizeof(tmp2),
                        level3, sizeof(level3) - 1, seed, sizeof(seed)))
    goto out;
  ret = 0;
out:
  memzero(tmp1, sizeof(tmp1));
  memzero(tmp2, sizeof(tmp2));
  return ret;
}

static void shift_left(u8 out[16], const u8 in[16])
{
  unsigned int carry = 0;
  int i;

  for (i = 15; i >= 0; i--) {
    unsigned int next = in[i] >> 7;

    out[i] = (in[i] << 1) | carry;
    carry = next;
  }
}

static u8 omac_byte(const u8 *a, size_t a_len,
                         const u8 *b, size_t pos)
{
  return pos < a_len ? a[pos] : b[pos - a_len];
}

void kuznyechik_omac2(u8 out[16], const u8 key[32],
                      const u8 *a, size_t a_len,
                      const u8 *b, size_t b_len)
{
  struct kuznyechik_ctx ctx;
  u8 state[16] = { 0 };
  u8 subkey1[16];
  u8 subkey2[16];
  u8 block[16];
  unsigned int msb;
  size_t data_len = a_len + b_len;
  size_t blocks = data_len ? (data_len + 15) / 16 : 1;
  size_t i;
  size_t last_len = data_len - (blocks - 1) * 16;

  kuznyechik_setkey(&ctx, key);
  kuznyechik_encrypt(&ctx, subkey1, state);
  msb = subkey1[0] & 0x80;
  shift_left(subkey1, subkey1);
  if (msb)
    subkey1[15] ^= 0x87;
  msb = subkey1[0] & 0x80;
  shift_left(subkey2, subkey1);
  if (msb)
    subkey2[15] ^= 0x87;

  for (i = 0; i + 1 < blocks; i++) {
    size_t j;

    for (j = 0; j < 16; j++)
      block[j] = state[j] ^ omac_byte(a, a_len, b, i * 16 + j);
    kuznyechik_encrypt(&ctx, state, block);
  }

  memset(block, 0, sizeof(block));
  if (last_len == 16) {
    for (i = 0; i < 16; i++)
      block[i] = omac_byte(a, a_len, b, (blocks - 1) * 16 + i) ^
                 subkey1[i] ^ state[i];
  } else {
    if (last_len)
      for (i = 0; i < last_len; i++)
        block[i] = omac_byte(a, a_len, b, (blocks - 1) * 16 + i);
    block[last_len] = 0x80;
    for (i = 0; i < 16; i++)
      block[i] ^= subkey2[i] ^ state[i];
  }
  kuznyechik_encrypt(&ctx, out, block);

  memzero(&ctx, sizeof(ctx));
  memzero(state, sizeof(state));
  memzero(subkey1, sizeof(subkey1));
  memzero(subkey2, sizeof(subkey2));
  memzero(block, sizeof(block));
}

void kuznyechik_omac(u8 out[16], const u8 key[32],
                     const u8 *data, size_t data_len)
{
  kuznyechik_omac2(out, key, data, data_len, NULL, 0);
}

static void ctr_inc(u8 ctr[16])
{
  int i;

  for (i = 15; i >= 0; i--)
    if (++ctr[i])
      break;
}

static void acpkm_next(struct kuznyechik_ctx *ctx)
{
  u8 d[16];
  u8 key[32];
  unsigned int i;

  for (i = 0; i < sizeof(d); i++)
    d[i] = 0x80 + i;
  kuznyechik_encrypt(ctx, key, d);
  for (i = 0; i < sizeof(d); i++)
    d[i] = 0x90 + i;
  kuznyechik_encrypt(ctx, key + 16, d);
  kuznyechik_setkey(ctx, key);
  memzero(key, sizeof(key));
}

void kuznyechik_ctr_acpkm(u8 *out, const u8 *in, size_t len,
                          const u8 key[32], const u8 iv[8],
                          size_t section_size)
{
  struct kuznyechik_ctx ctx;
  u8 ctr[16] = { 0 };
  u8 stream[16];
  size_t done = 0;
  size_t take;
  size_t i;

  kuznyechik_setkey(&ctx, key);
  memcpy(ctr, iv, 8);
  while (done < len) {
    if (done && section_size && done % section_size == 0)
      acpkm_next(&ctx);
    kuznyechik_encrypt(&ctx, stream, ctr);
    ctr_inc(ctr);
    take = len - done < 16 ? len - done : 16;
    for (i = 0; i < take; i++)
      out[done + i] = in[done + i] ^ stream[i];
    done += take;
  }

  memzero(&ctx, sizeof(ctx));
  memzero(stream, sizeof(stream));
}

void kuznyechik_kexp15(u8 out[48], const u8 key[32],
                       const u8 mac_key[32], const u8 enc_key[32],
                       const u8 iv[8])
{
  u8 data[40];

  memcpy(data, iv, 8);
  memcpy(data + 8, key, 32);
  memcpy(out, key, 32);
  kuznyechik_omac(out + 32, mac_key, data, sizeof(data));
  kuznyechik_ctr_acpkm(out, out, 48, enc_key, iv, 0);
  memzero(data, sizeof(data));
}

static int secure_equal(const u8 *a, const u8 *b, size_t len)
{
  unsigned int diff = 0;

  while (len--)
    diff |= *a++ ^ *b++;
  return diff == 0;
}

int kuznyechik_kimp15(u8 key[32], const u8 in[48],
                       const u8 mac_key[32], const u8 enc_key[32],
                       const u8 iv[8])
{
  u8 data[40];
  u8 plain[48];
  u8 mac[16];
  int ret = -1;

  kuznyechik_ctr_acpkm(plain, in, sizeof(plain), enc_key, iv, 0);
  memcpy(data, iv, 8);
  memcpy(data + 8, plain, 32);
  kuznyechik_omac(mac, mac_key, data, sizeof(data));
  if (secure_equal(mac, plain + 32, sizeof(mac))) {
    memcpy(key, plain, 32);
    ret = 0;
  }
  memzero(data, sizeof(data));
  memzero(plain, sizeof(plain));
  memzero(mac, sizeof(mac));
  return ret;
}
