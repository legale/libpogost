// SPDX-License-Identifier: GPL-2.0-or-later
/* ГОСТ Р 34.12-2015 (Kuznyechik), x86-64 SIMD backend. */

#include <stdint.h>

#include <libpogost/kuznyechik.h>

#include "../kuznyechik_internal.h"
#include "../generic/kuztable.h"

void kuznyechik_simd_encrypt_1way(const uint8_t *key, uint8_t *dst,
                                 const uint8_t *src, const uint8_t *table);
void kuznyechik_simd_decrypt_4way(const uint8_t *dekey, uint8_t *dst,
                                 const uint8_t *src, const uint8_t *inv_table,
                                 const uint8_t *inv_ls_table);

/* Загружаем слово из таблицы без выравнивания и без libc. */
static uint64_t load_le64(const uint8_t *src)
{
  uint64_t value = 0;
  unsigned int i;

  for (i = 0; i < 8; i++)
    value |= (uint64_t)src[i] << (i * 8);
  return value;
}

static void store_le64(uint8_t *dst, uint64_t value)
{
  unsigned int i;

  for (i = 0; i < 8; i++)
    dst[i] = value >> (i * 8);
}

static void kuz_l(uint8_t *out, const uint8_t *in,
                  const uint8_t table[16][256 * 16])
{
  uint64_t lo = 0;
  uint64_t hi = 0;
  const uint8_t *p;
  unsigned int i;

  for (i = 0; i < KUZNYECHIK_BLOCK_SIZE; i++) {
    p = &table[i][in[i] * KUZNYECHIK_BLOCK_SIZE];
    lo ^= load_le64(p);
    hi ^= load_le64(p + 8);
  }
  store_le64(out, lo);
  store_le64(out + 8, hi);
}

static void kuz_lsx(uint8_t *out, const uint8_t *in, const uint8_t *key)
{
  uint8_t block[KUZNYECHIK_BLOCK_SIZE];
  unsigned int i;

  for (i = 0; i < KUZNYECHIK_BLOCK_SIZE; i++)
    block[i] = in[i] ^ key[i];
  kuz_l(out, block, kuz_table);
}

static void kuz_subkey(uint8_t *out, const uint8_t *key, unsigned int n)
{
  uint8_t block[KUZNYECHIK_BLOCK_SIZE];

  kuz_lsx(block, key, kuz_key_table[n]);
  kuznyechik_xor_copy(out + 16, block, key + 16, 16);
  kuz_lsx(block, out + 16, kuz_key_table[n + 1]);
  kuznyechik_xor_copy(out, block, key, 16);
  kuz_lsx(block, out, kuz_key_table[n + 2]);
  kuznyechik_xor(out + 16, block, 16);
  kuz_lsx(block, out + 16, kuz_key_table[n + 3]);
  kuznyechik_xor(out, block, 16);
  kuz_lsx(block, out, kuz_key_table[n + 4]);
  kuznyechik_xor(out + 16, block, 16);
  kuz_lsx(block, out + 16, kuz_key_table[n + 5]);
  kuznyechik_xor(out, block, 16);
  kuz_lsx(block, out, kuz_key_table[n + 6]);
  kuznyechik_xor(out + 16, block, 16);
  kuz_lsx(block, out + 16, kuz_key_table[n + 7]);
  kuznyechik_xor(out, block, 16);
}

static int kuz_expand_key(struct kuznyechik_state *state,
                          const uint8_t key[KUZNYECHIK_KEY_SIZE])
{
  unsigned int i;

  if (!state || !key)
    return -1;
  kuznyechik_copy(state->key, key, KUZNYECHIK_KEY_SIZE);
  kuz_subkey(state->key + 32, state->key, 0);
  kuz_subkey(state->key + 64, state->key + 32, 8);
  kuz_subkey(state->key + 96, state->key + 64, 16);
  kuz_subkey(state->key + 128, state->key + 96, 24);
  for (i = 0; i < 10; i++)
    kuz_l(state->dekey + 16 * i, state->key + 16 * i, kuz_table_inv);
  return 0;
}

int kuznyechik_simd_setkey(struct kuznyechik_ctx *ctx,
                          const uint8_t key[KUZNYECHIK_KEY_SIZE])
{
  if (!ctx)
    return -1;
  return kuz_expand_key(kuznyechik_state(ctx), key);
}

void kuznyechik_simd_encrypt(const struct kuznyechik_ctx *ctx,
                            uint8_t out[KUZNYECHIK_BLOCK_SIZE],
                            const uint8_t in[KUZNYECHIK_BLOCK_SIZE])
{
  const struct kuznyechik_state *state = kuznyechik_const_state(ctx);

  kuznyechik_simd_encrypt_1way(state->key, out, in,
                              (const uint8_t *)kuz_table);
}

void kuznyechik_simd_decrypt(const struct kuznyechik_ctx *ctx,
                            uint8_t out[KUZNYECHIK_BLOCK_SIZE],
                            const uint8_t in[KUZNYECHIK_BLOCK_SIZE])
{
  const struct kuznyechik_state *state = kuznyechik_const_state(ctx);
  uint8_t input[64] = { 0 };
  uint8_t output[64];
  unsigned int i;

  kuznyechik_copy(input, in, KUZNYECHIK_BLOCK_SIZE);
  kuznyechik_simd_decrypt_4way(state->dekey, output, input,
                              (const uint8_t *)kuz_table_inv,
                              (const uint8_t *)kuz_table_inv_LS);
  for (i = 0; i < KUZNYECHIK_BLOCK_SIZE; i++)
    out[i] = pi_inv[output[i]] ^ state->key[i];
}
