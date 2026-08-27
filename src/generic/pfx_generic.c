/* SPDX-License-Identifier: Apache-2.0 */
#include <libpogost/pfx.h>

#include "gost28147_internal.h"
#include "hmac_streebog_internal.h"
#include "pbkdf2_internal.h"
#include "pfx_internal.h"
#include "sha1_internal.h"

#include <string.h>

static void memzero(void *ptr, size_t len)
{
  volatile u8 *p = ptr;

  while (len--) {
    *p++ = 0;
  }
}

static void sha1_hmac(u8 out[20], const u8 *key, size_t key_len,
                      const u8 *data, size_t data_len)
{
  struct sha1_ctx ctx;
  u8 pad[64];
  u8 inner[20];
  size_t i;

  memset(pad, 0x36, sizeof(pad));
  for (i = 0; i < key_len && i < sizeof(pad); i++)
    pad[i] ^= key[i];
  sha1_init(&ctx);
  sha1_update(&ctx, pad, sizeof(pad));
  sha1_update(&ctx, data, data_len);
  sha1_final(&ctx, inner);
  memset(pad, 0x5c, sizeof(pad));
  for (i = 0; i < key_len && i < sizeof(pad); i++)
    pad[i] ^= key[i];
  sha1_init(&ctx);
  sha1_update(&ctx, pad, sizeof(pad));
  sha1_update(&ctx, inner, sizeof(inner));
  sha1_final(&ctx, out);
  memzero(&ctx, sizeof(ctx));
  memzero(pad, sizeof(pad));
  memzero(inner, sizeof(inner));
}

static int pkcs12_sha1_key(u8 out[20], const u8 *pass, size_t pass_len,
                           const u8 *salt, size_t salt_len, u32 iter)
{
  u8 input[4096];
  u8 diversifier[64];
  u8 a[20];
  size_t salt_rep;
  size_t pass_rep;
  size_t input_len;
  size_t i;
  u32 round;

  /* Native PFX использует PKCS#12 KDF для SHA-1 MAC, а не PBKDF2. */
  if (!out || (!pass && pass_len) || !salt || !iter ||
      !salt_len || salt_len > sizeof(input) || pass_len > sizeof(input) ||
      pass_len + salt_len > sizeof(input))
    return -1;
  salt_rep = salt_len ? ((salt_len + 63) / 64) * 64 : 0;
  pass_rep = pass_len ? ((pass_len + 63) / 64) * 64 : 0;
  input_len = salt_rep + pass_rep;
  if (input_len > sizeof(input))
    return -1;
  for (i = 0; i < salt_rep; i++)
    input[i] = salt[i % salt_len];
  for (i = 0; i < pass_rep; i++)
    input[salt_rep + i] = pass_len ? pass[i % pass_len] : 0;
  memset(diversifier, 3, sizeof(diversifier));
  {
    struct sha1_ctx ctx;

    sha1_init(&ctx);
    sha1_update(&ctx, diversifier, sizeof(diversifier));
    sha1_update(&ctx, input, input_len);
    sha1_final(&ctx, a);
    for (round = 1; round < iter; round++) {
      sha1_init(&ctx);
      sha1_update(&ctx, a, sizeof(a));
      sha1_final(&ctx, a);
    }
    memcpy(out, a, sizeof(a));
  }
  memzero(input, sizeof(input));
  memzero(diversifier, sizeof(diversifier));
  memzero(a, sizeof(a));
  return 0;
}

int gost_pfx_sha1_mac(u8 out[20], const u8 *data, size_t data_len,
                      const u8 *pass_utf16be, size_t pass_len,
                      const u8 *salt, size_t salt_len, u32 iter)
{
  u8 key[20];
  int ret;

  if (!out || (!data && data_len) || (!pass_utf16be && pass_len) || !salt)
    return -1;
  ret = pkcs12_sha1_key(key, pass_utf16be, pass_len, salt, salt_len, iter);
  if (!ret)
    sha1_hmac(out, key, sizeof(key), data, data_len);
  memzero(key, sizeof(key));
  return ret;
}

int pfx_mac_streebog512(u8 out[64],
                         const u8 *data, size_t data_len,
                         const u8 *pass, size_t pass_len,
                         const u8 *salt, size_t salt_len, u32 iter)
{
  u8 dk[96];

  if (!out || (!data && data_len) || (!pass && pass_len) ||
      (!salt && salt_len) || !iter) {
    return -1;
  }
  if (pbkdf2_streebog512(dk, sizeof(dk), pass, pass_len, salt, salt_len,
                         iter)) {
    return -1;
  }
  hmac_streebog512(out, dk + 64, 32, data, data_len);
  memzero(dk, sizeof(dk));
  return 0;
}

int gost_pfx_gost89_encrypt(u8 *out, const u8 *in, size_t len,
                            const u8 *pass_utf8, size_t pass_len,
                            const u8 *salt, size_t salt_len,
                            u32 iter, const u8 iv[8])
{
  struct gost28147_state st;
  u8 key[32];
  int ret;

  if (!out || (!in && len) || (!pass_utf8 && pass_len) || !salt ||
      !salt_len || !iter || !iv) {
    return -1;
  }
  if (pbkdf2_streebog512(key, sizeof(key), pass_utf8, pass_len,
                         salt, salt_len, iter)) {
    return -1;
  }

  gost28147_setkey_raw(&st, key, gost28147_sbox_tc26_z);
  ret = gost28147_cfb_crypt(&st, out, in, len, iv, 1, 1);
  memzero(key, sizeof(key));
  memzero(&st, sizeof(st));
  return ret;
}

int gost_pfx_gost89_decrypt(u8 *out, const u8 *in, size_t len,
                            const u8 *pass_utf8, size_t pass_len,
                            const u8 *salt, size_t salt_len,
                            u32 iter, const u8 iv[8])
{
  struct gost28147_state st;
  u8 key[32];
  int ret;

  if (!out || (!in && len) || (!pass_utf8 && pass_len) || !salt ||
      !salt_len || !iter || !iv) {
    return -1;
  }
  if (pbkdf2_streebog512(key, sizeof(key), pass_utf8, pass_len,
                         salt, salt_len, iter)) {
    return -1;
  }
  gost28147_setkey_raw(&st, key, gost28147_sbox_tc26_z);
  ret = gost28147_cfb_crypt(&st, out, in, len, iv, 0, 1);
  memzero(key, sizeof(key));
  memzero(&st, sizeof(st));
  return ret;
}

int gost_pfx_mac(u8 out[GOST_PFX_MAC_SIZE],
                 const u8 *data, size_t data_len,
                 const u8 *pass_utf8, size_t pass_len,
                 const u8 *salt, size_t salt_len, u32 iter)
{
  return pfx_mac_streebog512(out, data, data_len, pass_utf8, pass_len,
                             salt, salt_len, iter);
}

int gost_pfx_cp80_wrap(u8 *enc,
                       u8 mac[GOST_PFX_CP80_MAC_SIZE],
                       const u8 *raw_key, size_t key_len,
                       const u8 *pass_utf16le, size_t pass_len,
                       const u8 *salt, size_t salt_len, u32 iter,
                       const u8 ukm[8])
{
  u8 key[32];
  int ret;

  if (!enc || !mac || !raw_key || !salt || !ukm) {
    return -1;
  }
  if (cryptopro_keybag_kdf(key, pass_utf16le, pass_len, salt, salt_len, iter)) {
    return -1;
  }
  ret = cryptopro_keybag_wrap(enc, mac, raw_key, key_len, key, ukm, 8, 1);
  memzero(key, sizeof(key));
  return ret;
}

int gost_pfx_cp80_encrypt(u8 *out, const u8 *blob, size_t blob_len,
                          const u8 *pass_utf16le, size_t pass_len,
                          const u8 *salt, size_t salt_len, u32 iter)
{
  u8 key[32];
  int ret;

  if (!out || (!blob && blob_len) || !salt) {
    return -1;
  }
  if (cryptopro_keybag_kdf(key, pass_utf16le, pass_len, salt, salt_len, iter)) {
    return -1;
  }
  ret = cryptopro_keybag_blob_crypt(out, blob, blob_len, key,
                                    salt, salt_len, 1);
  memzero(key, sizeof(key));
  return ret;
}
