/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LIBPOGOST_HMAC_STREEBOG_INTERNAL_H
#define LIBPOGOST_HMAC_STREEBOG_INTERNAL_H

#include <stddef.h>
#include <libpogost/types.h>

void hmac_streebog256(u8 out[32], const u8 *key, size_t key_len,
                      const u8 *data, size_t data_len);
void hmac_streebog512(u8 out[64], const u8 *key, size_t key_len,
                      const u8 *data, size_t data_len);
void hmac_streebog256_parts(u8 out[32], const u8 *key, size_t key_len,
                            const u8 *a, size_t a_len,
                            const u8 *b, size_t b_len,
                            const u8 *c, size_t c_len);
void hmac_streebog512_parts(u8 out[64], const u8 *key, size_t key_len,
                            const u8 *a, size_t a_len,
                            const u8 *b, size_t b_len);

#endif
