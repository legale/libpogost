/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LIBPOGOST_RC2_H
#define LIBPOGOST_RC2_H

#include <libpogost/types.h>

#define RC2_BLOCK_SIZE 8

struct rc2_key {
  u32 data[64];
};

void rc2_set_key(struct rc2_key *key, size_t len, const u8 *data, int bits);
void rc2_encrypt_block(const struct rc2_key *key, const u8 in[8], u8 out[8]);
void rc2_decrypt_block(const struct rc2_key *key, const u8 in[8], u8 out[8]);
void rc2_cbc_encrypt(const struct rc2_key *key, u8 iv[8], const u8 *in, u8 *out, size_t len);
void rc2_cbc_decrypt(const struct rc2_key *key, u8 iv[8], const u8 *in, u8 *out, size_t len);

#endif /* LIBPOGOST_RC2_H */
