/* SPDX-License-Identifier: Apache-2.0 */
#include <libpogost/gost_tls.h>
#include <libpogost/kuznyechik.h>
#include <libpogost/streebog.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void memzero(void *ptr, size_t len)
{
  volatile uint8_t *p = ptr;

  while (len--)
    *p++ = 0;
}

static void hmac_parts(uint8_t out[32], const uint8_t *key, size_t key_len,
                       const uint8_t *a, size_t a_len,
                       const uint8_t *b, size_t b_len,
                       const uint8_t *c, size_t c_len)
{
  struct streebog_ctx ctx;
  uint8_t key_block[64] = { 0 };
  uint8_t inner[32];
  uint8_t pad[64];
  size_t i;

  if (key_len > sizeof(key_block)) {
    streebog256(key_block, key, key_len);
  } else if (key_len) {
    memcpy(key_block, key, key_len);
  }

  for (i = 0; i < sizeof(pad); i++)
    pad[i] = key_block[i] ^ 0x36;
  streebog_init(&ctx, 256);
  streebog_update(&ctx, pad, sizeof(pad));
  streebog_update(&ctx, a, a_len);
  streebog_update(&ctx, b, b_len);
  streebog_update(&ctx, c, c_len);
  streebog_final(&ctx, inner);

  for (i = 0; i < sizeof(pad); i++)
    pad[i] = key_block[i] ^ 0x5c;
  streebog_init(&ctx, 256);
  streebog_update(&ctx, pad, sizeof(pad));
  streebog_update(&ctx, inner, sizeof(inner));
  streebog_final(&ctx, out);

  memzero(key_block, sizeof(key_block));
  memzero(inner, sizeof(inner));
  memzero(pad, sizeof(pad));
  memzero(&ctx, sizeof(ctx));
}

void gost_hmac_streebog256(uint8_t out[32], const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len)
{
  hmac_parts(out, key, key_len, data, data_len, NULL, 0, NULL, 0);
}

static size_t put_be(uint8_t out[sizeof(size_t)], size_t value)
{
  size_t pos = sizeof(size_t);

  do {
    out[--pos] = value & 0xff;
    value >>= 8;
  } while (value);
  memmove(out, out + pos, sizeof(size_t) - pos);
  return sizeof(size_t) - pos;
}

int gost_kdf_tree_256(uint8_t *out, size_t out_len,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *label, size_t label_len,
                      const uint8_t *seed, size_t seed_len)
{
  uint8_t suffix[1 + 255 + sizeof(size_t)];
  uint8_t len_buf[sizeof(size_t)];
  uint8_t counter;
  size_t len_len;
  size_t off;

  if (!out_len || out_len % 32 || out_len / 32 > 255 || seed_len > 255)
    return -1;

  len_len = put_be(len_buf, out_len * 8);
  suffix[0] = 0;
  memcpy(suffix + 1, seed, seed_len);
  memcpy(suffix + 1 + seed_len, len_buf, len_len);

  for (off = 0, counter = 1; off < out_len; off += 32, counter++)
    hmac_parts(out + off, key, key_len, &counter, 1, label, label_len,
               suffix, 1 + seed_len + len_len);

  memzero(suffix, sizeof(suffix));
  return 0;
}

int gost_tls_prf_256(uint8_t *out, size_t out_len,
                     const uint8_t *secret, size_t secret_len,
                     const char *label, const uint8_t *seed, size_t seed_len)
{
  uint8_t a[32];
  uint8_t block[32];
  size_t label_len = strlen(label);
  size_t take;

  hmac_parts(a, secret, secret_len, (const uint8_t *)label, label_len,
             seed, seed_len, NULL, 0);
  while (out_len) {
    hmac_parts(block, secret, secret_len, a, sizeof(a),
               (const uint8_t *)label, label_len, seed, seed_len);
    take = out_len < sizeof(block) ? out_len : sizeof(block);
    memcpy(out, block, take);
    out += take;
    out_len -= take;
    hmac_parts(a, secret, secret_len, a, sizeof(a), NULL, 0, NULL, 0);
  }

  memzero(a, sizeof(a));
  memzero(block, sizeof(block));
  return 0;
}

static uint64_t get_le64(const uint8_t in[8])
{
  uint64_t value = 0;
  unsigned int i;

  for (i = 0; i < 8; i++)
    value |= (uint64_t)in[i] << (8 * i);
  return value;
}

static void put_le64(uint8_t out[8], uint64_t value)
{
  unsigned int i;

  for (i = 0; i < 8; i++)
    out[i] = value >> (8 * i);
}

int gost_tls_tlstree_kuznyechik(uint8_t out[32], const uint8_t key[32],
                                const uint8_t seq[8])
{
  static const uint8_t level1[] = "level1";
  static const uint8_t level2[] = "level2";
  static const uint8_t level3[] = "level3";
  uint8_t seed[8];
  uint8_t tmp1[32];
  uint8_t tmp2[32];
  uint64_t n = get_le64(seq);
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

static void shift_left(uint8_t out[16], const uint8_t in[16])
{
  unsigned int carry = 0;
  int i;

  for (i = 15; i >= 0; i--) {
    unsigned int next = in[i] >> 7;

    out[i] = (in[i] << 1) | carry;
    carry = next;
  }
}

static uint8_t omac_byte(const uint8_t *a, size_t a_len,
                         const uint8_t *b, size_t pos)
{
  return pos < a_len ? a[pos] : b[pos - a_len];
}

void kuznyechik_omac2(uint8_t out[16], const uint8_t key[32],
                      const uint8_t *a, size_t a_len,
                      const uint8_t *b, size_t b_len)
{
  struct kuznyechik_ctx ctx;
  uint8_t state[16] = { 0 };
  uint8_t subkey1[16];
  uint8_t subkey2[16];
  uint8_t block[16];
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

void kuznyechik_omac(uint8_t out[16], const uint8_t key[32],
                     const uint8_t *data, size_t data_len)
{
  kuznyechik_omac2(out, key, data, data_len, NULL, 0);
}

static void ctr_inc(uint8_t ctr[16])
{
  int i;

  for (i = 15; i >= 0; i--)
    if (++ctr[i])
      break;
}

static void acpkm_next(struct kuznyechik_ctx *ctx)
{
  uint8_t d[16];
  uint8_t key[32];
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

void kuznyechik_ctr_acpkm(uint8_t *out, const uint8_t *in, size_t len,
                          const uint8_t key[32], const uint8_t iv[8],
                          size_t section_size)
{
  struct kuznyechik_ctx ctx;
  uint8_t ctr[16] = { 0 };
  uint8_t stream[16];
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

void kuznyechik_kexp15(uint8_t out[48], const uint8_t key[32],
                       const uint8_t mac_key[32], const uint8_t enc_key[32],
                       const uint8_t iv[8])
{
  uint8_t data[40];

  memcpy(data, iv, 8);
  memcpy(data + 8, key, 32);
  memcpy(out, key, 32);
  kuznyechik_omac(out + 32, mac_key, data, sizeof(data));
  kuznyechik_ctr_acpkm(out, out, 48, enc_key, iv, 0);
  memzero(data, sizeof(data));
}

static int secure_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
  unsigned int diff = 0;

  while (len--)
    diff |= *a++ ^ *b++;
  return diff == 0;
}

int kuznyechik_kimp15(uint8_t key[32], const uint8_t in[48],
                       const uint8_t mac_key[32], const uint8_t enc_key[32],
                       const uint8_t iv[8])
{
  uint8_t data[40];
  uint8_t plain[48];
  uint8_t mac[16];
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
