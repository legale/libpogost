/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-2-Clause */
#ifndef LIBPOGOST_GOST3410_H
#define LIBPOGOST_GOST3410_H

#include <libpogost/types.h>

#define GOST3410_256_KEY_SIZE 32
#define GOST3410_256_PUBLIC_SIZE 64
#define GOST3410_256_SIGNATURE_SIZE 64
#define GOST3410_256_DIGEST_SIZE 32

#define GOST3410_512_KEY_SIZE 64
#define GOST3410_512_PUBLIC_SIZE 128
#define GOST3410_512_SIGNATURE_SIZE 128
#define GOST3410_512_DIGEST_SIZE 64
#define GOST3410_512_UKM_SIZE 16

int gost3410_256a_public(
    u8 public_key[GOST3410_256_PUBLIC_SIZE],
    const u8 private_key[GOST3410_256_KEY_SIZE]);
int gost3410_256a_sign(
    u8 signature[GOST3410_256_SIGNATURE_SIZE],
    const u8 digest[GOST3410_256_DIGEST_SIZE],
    const u8 private_key[GOST3410_256_KEY_SIZE],
    const u8 nonce[GOST3410_256_KEY_SIZE]);
int gost3410_256a_verify(
    const u8 public_key[GOST3410_256_PUBLIC_SIZE],
    const u8 digest[GOST3410_256_DIGEST_SIZE],
    const u8 signature[GOST3410_256_SIGNATURE_SIZE]);

int gost3410_256tc26a_public(
    u8 public_key[GOST3410_256_PUBLIC_SIZE],
    const u8 private_key[GOST3410_256_KEY_SIZE]);
int gost3410_256tc26a_sign(
    u8 signature[GOST3410_256_SIGNATURE_SIZE],
    const u8 digest[GOST3410_256_DIGEST_SIZE],
    const u8 private_key[GOST3410_256_KEY_SIZE],
    const u8 nonce[GOST3410_256_KEY_SIZE]);
int gost3410_256tc26a_verify(
    const u8 public_key[GOST3410_256_PUBLIC_SIZE],
    const u8 digest[GOST3410_256_DIGEST_SIZE],
    const u8 signature[GOST3410_256_SIGNATURE_SIZE]);
int gost3410_256tc26a_vko(
    u8 shared_key[GOST3410_256_DIGEST_SIZE],
    const u8 public_key[GOST3410_256_PUBLIC_SIZE],
    const u8 private_key[GOST3410_256_KEY_SIZE],
    const u8 ukm[GOST3410_256_KEY_SIZE / 2]);

int gost3410_512a_public(
    u8 public_key[GOST3410_512_PUBLIC_SIZE],
    const u8 private_key[GOST3410_512_KEY_SIZE]);
int gost3410_512a_sign(
    u8 signature[GOST3410_512_SIGNATURE_SIZE],
    const u8 digest[GOST3410_512_DIGEST_SIZE],
    const u8 private_key[GOST3410_512_KEY_SIZE],
    const u8 nonce[GOST3410_512_KEY_SIZE]);
int gost3410_512a_verify(
    const u8 public_key[GOST3410_512_PUBLIC_SIZE],
    const u8 digest[GOST3410_512_DIGEST_SIZE],
    const u8 signature[GOST3410_512_SIGNATURE_SIZE]);
int gost3410_512a_vko(
    u8 shared_key[GOST3410_512_DIGEST_SIZE],
    const u8 public_key[GOST3410_512_PUBLIC_SIZE],
    const u8 private_key[GOST3410_512_KEY_SIZE],
    const u8 ukm[GOST3410_512_UKM_SIZE]);

#endif
