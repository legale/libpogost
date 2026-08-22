/* SPDX-License-Identifier: GPL-2.0 OR MIT */
#ifndef LIBPOGOST_CURVE25519_H
#define LIBPOGOST_CURVE25519_H

#include <libpogost/types.h>

#define POGOST_CURVE25519_KEY_SIZE 32

static inline void pogost_curve25519_clamp_secret(u8 secret[32])
{
	secret[0] &= 248;
	secret[31] = (secret[31] & 127) | 64;
}

void pogost_curve25519_generic(u8 out[32], const u8 scalar[32],
			       const u8 point[32]);
bool pogost_curve25519(u8 out[32], const u8 secret[32], const u8 point[32]);
bool pogost_curve25519_generate_public(u8 pub[32], const u8 secret[32]);

#endif
