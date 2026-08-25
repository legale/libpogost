/* SPDX-License-Identifier: OpenSSL */
#ifndef LIBPOGOST_GOST3411_94_INTERNAL_H
#define LIBPOGOST_GOST3411_94_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

void gost3411_94_cryptopro(uint8_t out[32], const uint8_t *data, size_t len);

#endif
