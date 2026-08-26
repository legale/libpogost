/* SPDX-License-Identifier: OpenSSL */
#ifndef LIBPOGOST_GOST3411_94_INTERNAL_H
#define LIBPOGOST_GOST3411_94_INTERNAL_H

#include <stddef.h>
#include <libpogost/types.h>

void gost3411_94_cryptopro(u8 out[32], const u8 *data, size_t len);
void gost3411_94_cryptopro_parts(u8 out[32],
                                 const u8 *a, size_t a_len,
                                 const u8 *b, size_t b_len,
                                 const u8 *c, size_t c_len);

#endif
