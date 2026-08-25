/* SPDX-License-Identifier: OpenSSL */
#ifndef LIBPOGOST_GOST3411_94_INTERNAL_H
#define LIBPOGOST_GOST3411_94_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

void gost3411_94_cryptopro(uint8_t out[32], const uint8_t *data, size_t len);
void gost3411_94_cryptopro_parts(uint8_t out[32],
                                 const uint8_t *a, size_t a_len,
                                 const uint8_t *b, size_t b_len,
                                 const uint8_t *c, size_t c_len);

#endif
