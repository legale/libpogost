/* SPDX-License-Identifier: Apache-2.0 */
#include <libpogost/pfx.h>

#include "gost28147_internal.h"
#include "hmac_streebog_internal.h"
#include "pbkdf2_internal.h"
#include "pfx_internal.h"

#include <string.h>

static void memzero(void *ptr, size_t len)
{
  volatile uint8_t *p = ptr;

  while (len--) {
    *p++ = 0;
  }
}

int pfx_mac_streebog512(uint8_t out[64],
                         const uint8_t *data, size_t data_len,
                         const uint8_t *pass, size_t pass_len,
                         const uint8_t *salt, size_t salt_len, uint32_t iter)
{
  uint8_t dk[96];

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

int gost_pfx_gost89_encrypt(uint8_t *out, const uint8_t *in, size_t len,
                            const uint8_t *pass_utf8, size_t pass_len,
                            const uint8_t *salt, size_t salt_len,
                            uint32_t iter, const uint8_t iv[8])
{
  struct gost28147_state st;
  uint8_t key[32];
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

int gost_pfx_mac(uint8_t out[GOST_PFX_MAC_SIZE],
                 const uint8_t *data, size_t data_len,
                 const uint8_t *pass_utf8, size_t pass_len,
                 const uint8_t *salt, size_t salt_len, uint32_t iter)
{
  return pfx_mac_streebog512(out, data, data_len, pass_utf8, pass_len,
                             salt, salt_len, iter);
}

int gost_pfx_cp80_wrap(uint8_t *enc,
                       uint8_t mac[GOST_PFX_CP80_MAC_SIZE],
                       const uint8_t *raw_key, size_t key_len,
                       const uint8_t *pass_utf16le, size_t pass_len,
                       const uint8_t *salt, size_t salt_len, uint32_t iter,
                       const uint8_t ukm[8])
{
  uint8_t key[32];
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

int gost_pfx_cp80_encrypt(uint8_t *out, const uint8_t *blob, size_t blob_len,
                          const uint8_t *pass_utf16le, size_t pass_len,
                          const uint8_t *salt, size_t salt_len, uint32_t iter)
{
  uint8_t key[32];
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
