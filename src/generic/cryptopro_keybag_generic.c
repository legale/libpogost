/* SPDX-License-Identifier: OpenSSL */
#include <libpogost/gost_tls.h>

#include "gost28147_internal.h"
#include "gost3411_94_internal.h"
#include "pfx_internal.h"

#include <string.h>

static void memzero(void *ptr, size_t len)
{
  volatile uint8_t *p = ptr;

  while (len--) {
    *p++ = 0;
  }
}

int cryptopro_keybag_kdf(uint8_t out[32],
                         const uint8_t *pass_utf16le, size_t pass_len,
                         const uint8_t *salt, size_t salt_len, uint32_t iter)
{
  uint8_t key[32];
  const uint8_t *cur = pass_utf16le;
  size_t cur_len = pass_len;
  uint32_t i;

  if (!out || (!pass_utf16le && pass_len) || !salt || salt_len < 8 ||
      !iter || iter > 1000000) {
    return -1;
  }

  for (i = 1; i <= iter; i++) {
    uint8_t ctr[2] = { i >> 8, i };

    gost3411_94_cryptopro_parts(key, cur, cur_len, salt, salt_len,
                                ctr, sizeof(ctr));
    cur = key;
    cur_len = sizeof(key);
  }
  memcpy(out, key, sizeof(key));
  memzero(key, sizeof(key));
  return 0;
}

int cryptopro_keybag_wrap(uint8_t *out, uint8_t mac[4],
                          const uint8_t *in, size_t len,
                          const uint8_t key[32],
                          const uint8_t *ukm, size_t ukm_len, int enc)
{
  static const uint8_t label[4] = { 0x26, 0xbd, 0xb8, 0x78 };
  struct gost28147_state st;
  uint8_t ke[32];
  size_t off;
  int ret = -1;

  if (!out || !mac || !in || !key || !ukm ||
      (len != 32 && len != 64) || ukm_len != 8 ||
      (enc != 0 && enc != 1)) {
    return -1;
  }
  if (gost_kdf_tree_256(ke, sizeof(ke), key, 32, label, sizeof(label),
                        ukm, ukm_len)) {
    return -1;
  }

  gost28147_setkey_raw(&st, ke, gost28147_sbox_cryptopro_a);
  for (off = 0; off < len; off += 8) {
    if (enc) {
      gost28147_encrypt_raw(&st, out + off, in + off);
    } else {
      gost28147_decrypt_raw(&st, out + off, in + off);
    }
  }
  if (gost28147_mac4_raw(&st, mac, ukm, enc ? in : out, len)) {
    goto out;
  }
  ret = 0;
out:
  memzero(ke, sizeof(ke));
  memzero(&st, sizeof(st));
  return ret;
}

int cryptopro_keybag_blob_crypt(uint8_t *out, const uint8_t *in, size_t len,
                                const uint8_t key[32],
                                const uint8_t *salt, size_t salt_len, int enc)
{
  struct gost28147_state st;
  uint8_t iv[8];
  int ret;

  if (!out || (!in && len) || !key || !salt || salt_len < sizeof(iv) ||
      (enc != 0 && enc != 1)) {
    return -1;
  }
  memcpy(iv, salt, sizeof(iv));
  gost28147_setkey_raw(&st, key, gost28147_sbox_cryptopro_a);
  ret = gost28147_cfb_crypt(&st, out, in, len, iv, enc, 0);
  memzero(iv, sizeof(iv));
  memzero(&st, sizeof(st));
  return ret;
}
