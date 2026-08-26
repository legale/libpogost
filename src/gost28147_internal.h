/* SPDX-License-Identifier: MIT */
#ifndef LIBPOGOST_GOST28147_INTERNAL_H
#define LIBPOGOST_GOST28147_INTERNAL_H

#include <stddef.h>
#include <libpogost/types.h>

struct gost28147_state {
  u32 key[8];
  const u8 (*sbox)[16];
};

extern const u8 gost28147_sbox_cryptopro_a[8][16];
extern const u8 gost28147_sbox_cryptopro_3411[8][16];
extern const u8 gost28147_sbox_tc26_z[8][16];

void gost28147_setkey_raw(struct gost28147_state *st, const u8 key[32],
                          const u8 sbox[8][16]);
void gost28147_encrypt_raw(const struct gost28147_state *st, u8 out[8],
                           const u8 in[8]);
void gost28147_decrypt_raw(const struct gost28147_state *st, u8 out[8],
                           const u8 in[8]);
int gost28147_mac4_raw(const struct gost28147_state *st, u8 out[4],
                       const u8 iv[8], const u8 *in, size_t len);
int gost28147_cfb_crypt(struct gost28147_state *st, u8 *out,
                        const u8 *in, size_t len, const u8 iv[8],
                        int enc, int mesh);

#endif
