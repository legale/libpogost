/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LIBPOGOST_HMAC_STREEBOG_INTERNAL_H
#define LIBPOGOST_HMAC_STREEBOG_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

void hmac_streebog256(uint8_t out[32], const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len);
void hmac_streebog512(uint8_t out[64], const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len);
void hmac_streebog256_parts(uint8_t out[32], const uint8_t *key, size_t key_len,
                            const uint8_t *a, size_t a_len,
                            const uint8_t *b, size_t b_len,
                            const uint8_t *c, size_t c_len);
void hmac_streebog512_parts(uint8_t out[64], const uint8_t *key, size_t key_len,
                            const uint8_t *a, size_t a_len,
                            const uint8_t *b, size_t b_len);

#endif
