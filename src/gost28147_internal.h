/* SPDX-License-Identifier: MIT */
#ifndef LIBPOGOST_GOST28147_INTERNAL_H
#define LIBPOGOST_GOST28147_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

struct gost28147_state {
  uint32_t key[8];
  const uint8_t (*sbox)[16];
};

extern const uint8_t gost28147_sbox_cryptopro_a[8][16];
extern const uint8_t gost28147_sbox_cryptopro_3411[8][16];
extern const uint8_t gost28147_sbox_tc26_z[8][16];

void gost28147_setkey_raw(struct gost28147_state *st, const uint8_t key[32],
                          const uint8_t sbox[8][16]);
void gost28147_encrypt_raw(const struct gost28147_state *st, uint8_t out[8],
                           const uint8_t in[8]);
void gost28147_decrypt_raw(const struct gost28147_state *st, uint8_t out[8],
                           const uint8_t in[8]);
int gost28147_mac4_raw(const struct gost28147_state *st, uint8_t out[4],
                       const uint8_t iv[8], const uint8_t *in, size_t len);
int gost28147_cfb_crypt(struct gost28147_state *st, uint8_t *out,
                        const uint8_t *in, size_t len, const uint8_t iv[8],
                        int enc, int mesh);

#endif
