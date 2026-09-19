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

/* --- TLS 1.3 primitives (RFC 9058, RFC 9367) --- */

static u64 get_be64(const u8 in[8])
{
  u64 v = 0;
  int i;
  for (i = 0; i < 8; i++)
    v = (v << 8) | in[i];
  return v;
}

static void put_be64(u8 out[8], u64 v)
{
  int i;
  for (i = 7; i >= 0; i--) {
    out[i] = v & 0xff;
    v >>= 8;
  }
}

static void put_be16(u8 out[2], u16 v)
{
  out[0] = (v >> 8) & 0xff;
  out[1] = v & 0xff;
}

static void gf128_mul(u8 out[16], const u8 x[16], const u8 y[16])
{
  u64 x_hi = get_be64(x);
  u64 x_lo = get_be64(x + 8);
  u64 y_hi = get_be64(y);
  u64 y_lo = get_be64(y + 8);
  u64 res_hi = 0, res_lo = 0;
  int i;

  for (i = 0; i < 64; i++) {
    if ((y_lo >> i) & 1) {
      res_hi ^= x_hi;
      res_lo ^= x_lo;
    }
    u64 msb = (x_hi >> 63) & 1;
    x_hi = (x_hi << 1) | (x_lo >> 63);
    x_lo = (x_lo << 1);
    if (msb)
      x_lo ^= 0x87;
  }
  for (i = 0; i < 64; i++) {
    if ((y_hi >> i) & 1) {
      res_hi ^= x_hi;
      res_lo ^= x_lo;
    }
    u64 msb = (x_hi >> 63) & 1;
    x_hi = (x_hi << 1) | (x_lo >> 63);
    x_lo = (x_lo << 1);
    if (msb)
      x_lo ^= 0x87;
  }
  put_be64(out, res_hi);
  put_be64(out + 8, res_lo);
}

static void mgm_incr_r(u8 b[16])
{
  u64 r = get_be64(b + 8);
  put_be64(b + 8, r + 1);
}

static void mgm_incr_l(u8 b[16])
{
  u64 l = get_be64(b);
  put_be64(b, l + 1);
}

void gost_tls13_make_nonce(u8 out_nonce[16], const u8 iv[16], u64 seq)
{
  int i;
  memcpy(out_nonce, iv, 16);
  for (i = 0; i < 8; i++)
    out_nonce[15 - i] ^= (u8)((seq >> (8 * i)) & 0xff);
  out_nonce[0] &= 0x7f;
}

int kuznyechik_mgm_encrypt(u8 *out, u8 tag[16], const u8 key[32],
                           const u8 nonce[16], const u8 *aad, size_t aad_len,
                           const u8 *in, size_t in_len)
{
  struct kuznyechik_ctx ctx;
  u8 y[16], z[16], sum[16];
  size_t p_done = 0, aad_done = 0, c_done = 0;
  int i;

  kuznyechik_setkey(&ctx, key);

  if (in_len > 0) {
    memcpy(y, nonce, 16);
    y[0] &= 0x7f;
    kuznyechik_encrypt(&ctx, y, y);

    while (p_done < in_len) {
      u8 stream[16];
      size_t take = in_len - p_done < 16 ? in_len - p_done : 16;
      kuznyechik_encrypt(&ctx, stream, y);
      for (i = 0; i < (int)take; i++)
        out[p_done + i] = in[p_done + i] ^ stream[i];
      mgm_incr_r(y);
      p_done += take;
    }
  }

  memcpy(z, nonce, 16);
  z[0] |= 0x80;
  kuznyechik_encrypt(&ctx, z, z);

  memset(sum, 0, sizeof(sum));

  while (aad_done < aad_len) {
    u8 a_block[16] = { 0 };
    u8 h[16], prod[16];
    size_t take = aad_len - aad_done < 16 ? aad_len - aad_done : 16;
    memcpy(a_block, aad + aad_done, take);

    kuznyechik_encrypt(&ctx, h, z);
    gf128_mul(prod, h, a_block);
    for (i = 0; i < 16; i++)
      sum[i] ^= prod[i];

    mgm_incr_l(z);
    aad_done += take;
  }

  while (c_done < in_len) {
    u8 c_block[16] = { 0 };
    u8 h[16], prod[16];
    size_t take = in_len - c_done < 16 ? in_len - c_done : 16;
    memcpy(c_block, out + c_done, take);

    kuznyechik_encrypt(&ctx, h, z);
    gf128_mul(prod, h, c_block);
    for (i = 0; i < 16; i++)
      sum[i] ^= prod[i];

    mgm_incr_l(z);
    c_done += take;
  }

  {
    u8 h[16], len_block[16], prod[16];
    put_be64(len_block, (u64)aad_len * 8);
    put_be64(len_block + 8, (u64)in_len * 8);

    kuznyechik_encrypt(&ctx, h, z);
    gf128_mul(prod, h, len_block);
    for (i = 0; i < 16; i++)
      sum[i] ^= prod[i];

    kuznyechik_encrypt(&ctx, tag, sum);
  }

  memzero(&ctx, sizeof(ctx));
  memzero(y, sizeof(y));
  memzero(z, sizeof(z));
  memzero(sum, sizeof(sum));
  return 0;
}

int kuznyechik_mgm_decrypt(u8 *out, const u8 key[32],
                           const u8 nonce[16], const u8 *aad, size_t aad_len,
                           const u8 *in, size_t in_len, const u8 tag[16])
{
  struct kuznyechik_ctx ctx;
  u8 y[16], z[16], sum[16], calc_tag[16];
  size_t p_done = 0, aad_done = 0, c_done = 0;
  int i, ret = -1;

  kuznyechik_setkey(&ctx, key);

  memcpy(z, nonce, 16);
  z[0] |= 0x80;
  kuznyechik_encrypt(&ctx, z, z);

  memset(sum, 0, sizeof(sum));

  while (aad_done < aad_len) {
    u8 a_block[16] = { 0 };
    u8 h[16], prod[16];
    size_t take = aad_len - aad_done < 16 ? aad_len - aad_done : 16;
    memcpy(a_block, aad + aad_done, take);

    kuznyechik_encrypt(&ctx, h, z);
    gf128_mul(prod, h, a_block);
    for (i = 0; i < 16; i++)
      sum[i] ^= prod[i];

    mgm_incr_l(z);
    aad_done += take;
  }

  while (c_done < in_len) {
    u8 c_block[16] = { 0 };
    u8 h[16], prod[16];
    size_t take = in_len - c_done < 16 ? in_len - c_done : 16;
    memcpy(c_block, in + c_done, take);

    kuznyechik_encrypt(&ctx, h, z);
    gf128_mul(prod, h, c_block);
    for (i = 0; i < 16; i++)
      sum[i] ^= prod[i];

    mgm_incr_l(z);
    c_done += take;
  }

  {
    u8 h[16], len_block[16], prod[16];
    put_be64(len_block, (u64)aad_len * 8);
    put_be64(len_block + 8, (u64)in_len * 8);

    kuznyechik_encrypt(&ctx, h, z);
    gf128_mul(prod, h, len_block);
    for (i = 0; i < 16; i++)
      sum[i] ^= prod[i];

    kuznyechik_encrypt(&ctx, calc_tag, sum);
  }

  if (!secure_equal(calc_tag, tag, 16))
    goto out;

  if (in_len > 0) {
    memcpy(y, nonce, 16);
    y[0] &= 0x7f;
    kuznyechik_encrypt(&ctx, y, y);

    while (p_done < in_len) {
      u8 stream[16];
      size_t take = in_len - p_done < 16 ? in_len - p_done : 16;
      kuznyechik_encrypt(&ctx, stream, y);
      for (i = 0; i < (int)take; i++)
        out[p_done + i] = in[p_done + i] ^ stream[i];
      mgm_incr_r(y);
      p_done += take;
    }
  }

  ret = 0;
out:
  if (ret != 0 && in_len > 0)
    memzero(out, in_len);
  memzero(&ctx, sizeof(ctx));
  memzero(y, sizeof(y));
  memzero(z, sizeof(z));
  memzero(sum, sizeof(sum));
  memzero(calc_tag, sizeof(calc_tag));
  return ret;
}

int gost_tls13_tlstree_kuznyechik_mgm_l(u8 out[32], const u8 key[32], u64 seq)
{
  static const u8 level1[] = "level1";
  static const u8 level2[] = "level2";
  static const u8 level3[] = "level3";
  u8 seed[8];
  u8 tmp1[32];
  u8 tmp2[32];
  int ret = -1;

  put_be64(seed, seq & UINT64_C(0xf800000000000000));
  if (gost_kdf_tree_256(tmp1, sizeof(tmp1), key, 32,
                        level1, sizeof(level1) - 1, seed, sizeof(seed)))
    goto out;

  put_be64(seed, seq & UINT64_C(0xfffffff000000000));
  if (gost_kdf_tree_256(tmp2, sizeof(tmp2), tmp1, sizeof(tmp1),
                        level2, sizeof(level2) - 1, seed, sizeof(seed)))
    goto out;

  put_be64(seed, seq & UINT64_C(0xffffffffffffe000));
  if (gost_kdf_tree_256(out, 32, tmp2, sizeof(tmp2),
                        level3, sizeof(level3) - 1, seed, sizeof(seed)))
    goto out;

  ret = 0;
out:
  memzero(tmp1, sizeof(tmp1));
  memzero(tmp2, sizeof(tmp2));
  return ret;
}

int gost_tls13_tlstree_kuznyechik_mgm_s(u8 out[32], const u8 key[32], u64 seq)
{
  static const u8 level1[] = "level1";
  static const u8 level2[] = "level2";
  static const u8 level3[] = "level3";
  u8 seed[8];
  u8 tmp1[32];
  u8 tmp2[32];
  int ret = -1;

  put_be64(seed, seq & UINT64_C(0xffffffffe0000000));
  if (gost_kdf_tree_256(tmp1, sizeof(tmp1), key, 32,
                        level1, sizeof(level1) - 1, seed, sizeof(seed)))
    goto out;

  put_be64(seed, seq & UINT64_C(0xffffffffffff0000));
  if (gost_kdf_tree_256(tmp2, sizeof(tmp2), tmp1, sizeof(tmp1),
                        level2, sizeof(level2) - 1, seed, sizeof(seed)))
    goto out;

  put_be64(seed, seq & UINT64_C(0xfffffffffffffff8));
  if (gost_kdf_tree_256(out, 32, tmp2, sizeof(tmp2),
                        level3, sizeof(level3) - 1, seed, sizeof(seed)))
    goto out;

  ret = 0;
out:
  memzero(tmp1, sizeof(tmp1));
  memzero(tmp2, sizeof(tmp2));
  return ret;
}

int gost_tls13_hkdf_extract(u8 prk[32], const u8 *salt, size_t salt_len,
                            const u8 *ikm, size_t ikm_len)
{
  static const u8 zeros[32] = { 0 };
  if (!salt || salt_len == 0) {
    salt = zeros;
    salt_len = 32;
  }
  gost_hmac_streebog256(prk, salt, salt_len, ikm, ikm_len);
  return 0;
}

int gost_tls13_hkdf_expand(u8 *okm, size_t okm_len, const u8 prk[32],
                           const u8 *info, size_t info_len)
{
  u8 t[32];
  u8 counter = 1;
  size_t done = 0;

  if (okm_len > 255 * 32)
    return -1;

  while (done < okm_len) {
    size_t take = okm_len - done < 32 ? okm_len - done : 32;

    if (counter == 1) {
      u8 in_buf[512];
      if (info_len + 1 > sizeof(in_buf))
        return -1;
      memcpy(in_buf, info, info_len);
      in_buf[info_len] = counter;
      gost_hmac_streebog256(t, prk, 32, in_buf, info_len + 1);
    } else {
      u8 in_buf[512];
      if (32 + info_len + 1 > sizeof(in_buf))
        return -1;
      memcpy(in_buf, t, 32);
      memcpy(in_buf + 32, info, info_len);
      in_buf[32 + info_len] = counter;
      gost_hmac_streebog256(t, prk, 32, in_buf, 32 + info_len + 1);
    }
    memcpy(okm + done, t, take);
    done += take;
    counter++;
  }
  memzero(t, sizeof(t));
  return 0;
}

int gost_tls13_hkdf_expand_label(u8 *okm, size_t okm_len, const u8 secret[32],
                                 const char *label,
                                 const u8 *context, size_t context_len)
{
  u8 hkdf_label[512];
  size_t label_len = strlen(label);
  size_t full_label_len = 6 + label_len;
  size_t pos = 0;

  if (full_label_len > 255 || context_len > 255 ||
      2 + 1 + full_label_len + 1 + context_len > sizeof(hkdf_label))
    return -1;

  put_be16(hkdf_label + pos, (u16)okm_len);
  pos += 2;
  hkdf_label[pos++] = (u8)full_label_len;
  memcpy(hkdf_label + pos, "tls13 ", 6);
  pos += 6;
  memcpy(hkdf_label + pos, label, label_len);
  pos += label_len;
  hkdf_label[pos++] = (u8)context_len;
  if (context_len) {
    memcpy(hkdf_label + pos, context, context_len);
    pos += context_len;
  }

  return gost_tls13_hkdf_expand(okm, okm_len, secret, hkdf_label, pos);
}
