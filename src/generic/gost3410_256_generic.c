/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-2-Clause */
/*
 * GOST R 34.10-2012, CryptoPro XchA paramSet.
 *
 * Public keys and digests use little-endian representation. Signatures use
 * the X.509 s || r big-endian representation.
 */

#include <libpogost/gost3410.h>

#include <string.h>

#include "ecc_generic.h"
#include "gost3410_256_internal.h"

#define NDIGITS 4

static u64 curve_g_x[NDIGITS] = {
  0x0000000000000001ULL, 0, 0, 0
};

static u64 curve_g_y[NDIGITS] = {
  0x22acc99c9e9f1e14ULL, 0x35294f2ddf23e3b1ULL,
  0x27df505a453f2b76ULL, 0x8d91e471e0989cdaULL
};

static u64 curve_p[NDIGITS] = {
  0xfffffffffffffd97ULL, 0xffffffffffffffffULL,
  0xffffffffffffffffULL, 0xffffffffffffffffULL
};

static u64 curve_n[NDIGITS] = {
  0x45841b09b761b893ULL, 0x6c611070995ad100ULL,
  0xffffffffffffffffULL, 0xffffffffffffffffULL
};

static u64 curve_a[NDIGITS] = {
  0xfffffffffffffd94ULL, 0xffffffffffffffffULL,
  0xffffffffffffffffULL, 0xffffffffffffffffULL
};

static u64 curve_b[NDIGITS] = {
  0x00000000000000a6ULL, 0, 0, 0
};

static struct ecc_curve curve = {
  .name = "gost_cp256_xcha",
  .g = ECC_POINT_INIT(curve_g_x, curve_g_y, NDIGITS),
  .p = curve_p,
  .n = curve_n,
  .a = curve_a,
  .b = curve_b
};

static void vli_to_le(uint8_t *out, const u64 *in)
{
  unsigned int i;
  unsigned int j;

  for (i = 0; i < NDIGITS; i++)
    for (j = 0; j < 8; j++)
      out[i * 8 + j] = (uint8_t)(in[i] >> (j * 8));
}

static void vli_to_be(uint8_t *out, const u64 *in)
{
  uint8_t tmp[GOST3410_256_KEY_SIZE];
  unsigned int i;

  vli_to_le(tmp, in);
  for (i = 0; i < sizeof(tmp); i++)
    out[i] = tmp[sizeof(tmp) - 1 - i];
  memset(tmp, 0, sizeof(tmp));
}

static int scalar_valid(const u64 *scalar)
{
  return !vli_is_zero(scalar, NDIGITS) &&
         vli_cmp(scalar, curve.n, NDIGITS) < 0;
}

static void digest_scalar(u64 *e, const uint8_t *digest)
{
  vli_from_le64(e, digest, NDIGITS);
  if (vli_cmp(e, curve.n, NDIGITS) >= 0)
    vli_sub(e, e, curve.n, NDIGITS);
  if (vli_is_zero(e, NDIGITS))
    e[0] = 1;
}

#if !defined(__SIZEOF_INT128__)
static void point_mult(struct ecc_point *result, const struct ecc_point *point,
                       const u64 *scalar)
{
  u64 zero[NDIGITS] = { 0 };

  ecc_point_mult_shamir(result, scalar, point, zero, point, &curve);
}
#endif

int gost3410_256a_public(
    uint8_t public_key[GOST3410_256_PUBLIC_SIZE],
    const uint8_t private_key[GOST3410_256_KEY_SIZE])
{
  u64 d[NDIGITS];
#if !defined(__SIZEOF_INT128__)
  u64 x[NDIGITS];
  u64 y[NDIGITS];
  struct ecc_point q = ECC_POINT_INIT(x, y, NDIGITS);
#endif

  vli_from_le64(d, private_key, NDIGITS);
  if (!scalar_valid(d))
    return -1;

#if defined(__SIZEOF_INT128__)
  gost3410_256a_point_mul_g(public_key,
                           public_key + GOST3410_256_KEY_SIZE, private_key);
#else
  point_mult(&q, &curve.g, d);
  vli_to_le(public_key, q.x);
  vli_to_le(public_key + GOST3410_256_KEY_SIZE, q.y);
#endif
  memset(d, 0, sizeof(d));
  return 0;
}

int gost3410_256a_sign(
    uint8_t signature[GOST3410_256_SIGNATURE_SIZE],
    const uint8_t digest[GOST3410_256_DIGEST_SIZE],
    const uint8_t private_key[GOST3410_256_KEY_SIZE],
    const uint8_t nonce[GOST3410_256_KEY_SIZE])
{
  u64 d[NDIGITS];
  u64 e[NDIGITS];
  u64 k[NDIGITS];
  u64 r[NDIGITS];
  u64 s[NDIGITS];
  u64 t[NDIGITS];
  u64 x[NDIGITS];
  u64 y[NDIGITS];
  struct ecc_point c = ECC_POINT_INIT(x, y, NDIGITS);
#if defined(__SIZEOF_INT128__)
  uint8_t point_x[GOST3410_256_KEY_SIZE];
  uint8_t point_y[GOST3410_256_KEY_SIZE];
#endif

  vli_from_le64(d, private_key, NDIGITS);
  vli_from_le64(k, nonce, NDIGITS);
  if (!scalar_valid(d) || !scalar_valid(k))
    return -1;

  digest_scalar(e, digest);
#if defined(__SIZEOF_INT128__)
  gost3410_256a_point_mul_g(point_x, point_y, nonce);
  vli_from_le64(c.x, point_x, NDIGITS);
#else
  point_mult(&c, &curve.g, k);
#endif
  memcpy(r, c.x, sizeof(r));
  if (vli_cmp(r, curve.n, NDIGITS) >= 0)
    vli_sub(r, r, curve.n, NDIGITS);
  if (vli_is_zero(r, NDIGITS))
    return -1;

  vli_mod_mult_slow(s, d, r, curve.n, NDIGITS);
  vli_mod_mult_slow(t, k, e, curve.n, NDIGITS);
  vli_mod_add_generic(s, s, t, curve.n, NDIGITS);
  if (vli_is_zero(s, NDIGITS))
    return -1;

  vli_to_be(signature, s);
  vli_to_be(signature + GOST3410_256_KEY_SIZE, r);
  memset(d, 0, sizeof(d));
  memset(e, 0, sizeof(e));
  memset(k, 0, sizeof(k));
  memset(t, 0, sizeof(t));
  return 0;
}

int gost3410_256a_verify(
    const uint8_t public_key[GOST3410_256_PUBLIC_SIZE],
    const uint8_t digest[GOST3410_256_DIGEST_SIZE],
    const uint8_t signature[GOST3410_256_SIGNATURE_SIZE])
{
  u64 qx[NDIGITS];
  u64 qy[NDIGITS];
  u64 r[NDIGITS];
  u64 s[NDIGITS];
  u64 e[NDIGITS];
  u64 z1[NDIGITS];
  u64 z2[NDIGITS];
  u64 cx[NDIGITS];
  u64 cy[NDIGITS];
  struct ecc_point q = ECC_POINT_INIT(qx, qy, NDIGITS);
  struct ecc_point c = ECC_POINT_INIT(cx, cy, NDIGITS);
#if defined(__SIZEOF_INT128__)
  uint8_t scalar1[GOST3410_256_KEY_SIZE];
  uint8_t scalar2[GOST3410_256_KEY_SIZE];
  uint8_t point_x[GOST3410_256_KEY_SIZE];
  uint8_t point_y[GOST3410_256_KEY_SIZE];
#endif

  vli_from_le64(q.x, public_key, NDIGITS);
  vli_from_le64(q.y, public_key + GOST3410_256_KEY_SIZE, NDIGITS);
  vli_from_be64(s, signature, NDIGITS);
  vli_from_be64(r, signature + GOST3410_256_KEY_SIZE, NDIGITS);
  if (!ecc_point_valid_generic(&curve, &q) ||
      !scalar_valid(r) || !scalar_valid(s))
    return -1;

  digest_scalar(e, digest);
  vli_mod_inv(e, e, curve.n, NDIGITS);
  vli_mod_mult_slow(z1, s, e, curve.n, NDIGITS);
  vli_sub(z2, curve.n, r, NDIGITS);
  vli_mod_mult_slow(z2, z2, e, curve.n, NDIGITS);
#if defined(__SIZEOF_INT128__)
  vli_to_le(scalar1, z1);
  vli_to_le(scalar2, z2);
  gost3410_256a_point_mul_two(point_x, point_y, scalar1, scalar2,
                             public_key,
                             public_key + GOST3410_256_KEY_SIZE);
  vli_from_le64(c.x, point_x, NDIGITS);
  vli_from_le64(c.y, point_y, NDIGITS);
#else
  if (vli_cmp(q.x, curve.g.x, NDIGITS) == 0 &&
      vli_cmp(q.y, curve.g.y, NDIGITS) == 0) {
    vli_mod_add_generic(z1, z1, z2, curve.n, NDIGITS);
    if (vli_is_zero(z1, NDIGITS))
      return -1;
    point_mult(&c, &curve.g, z1);
  } else {
    ecc_point_mult_shamir(&c, z1, &curve.g, z2, &q, &curve);
  }
#endif
  if (vli_cmp(c.x, curve.n, NDIGITS) >= 0)
    vli_sub(c.x, c.x, curve.n, NDIGITS);
  return vli_cmp(c.x, r, NDIGITS) == 0 ? 0 : -1;
}
