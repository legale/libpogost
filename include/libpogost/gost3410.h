/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-2-Clause */
#ifndef LIBPOGOST_GOST3410_H
#define LIBPOGOST_GOST3410_H

#include <stdint.h>

#define GOST3410_512_KEY_SIZE 64
#define GOST3410_512_PUBLIC_SIZE 128
#define GOST3410_512_SIGNATURE_SIZE 128
#define GOST3410_512_DIGEST_SIZE 64
#define GOST3410_512_UKM_SIZE 16

int gost3410_512a_public(
    uint8_t public_key[GOST3410_512_PUBLIC_SIZE],
    const uint8_t private_key[GOST3410_512_KEY_SIZE]);
int gost3410_512a_sign(
    uint8_t signature[GOST3410_512_SIGNATURE_SIZE],
    const uint8_t digest[GOST3410_512_DIGEST_SIZE],
    const uint8_t private_key[GOST3410_512_KEY_SIZE],
    const uint8_t nonce[GOST3410_512_KEY_SIZE]);
int gost3410_512a_verify(
    const uint8_t public_key[GOST3410_512_PUBLIC_SIZE],
    const uint8_t digest[GOST3410_512_DIGEST_SIZE],
    const uint8_t signature[GOST3410_512_SIGNATURE_SIZE]);
int gost3410_512a_vko(
    uint8_t shared_key[GOST3410_512_DIGEST_SIZE],
    const uint8_t public_key[GOST3410_512_PUBLIC_SIZE],
    const uint8_t private_key[GOST3410_512_KEY_SIZE],
    const uint8_t ukm[GOST3410_512_UKM_SIZE]);

#endif
