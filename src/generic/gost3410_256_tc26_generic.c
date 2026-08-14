/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-2-Clause */
/*
 * GOST R 34.10-2012, TC26 256-bit paramSetA.
 *
 * The parameters are the same as the TC26 paramSetA parameters used by the
 * gost-openssl engine. Public keys and digests use little-endian encoding.
 * Signatures use the X.509 s || r big-endian representation.
 */

#include <libpogost/gost3410.h>
#include <libpogost/streebog.h>

#include <string.h>

#include "ecc_generic.h"

#define NDIGITS 4

static u64 curve_g_x[NDIGITS] = {
  0x8b2582fe742daa28ULL, 0x658b9196932e02c7ULL,
  0x880923425712b2bbULL, 0x91e38443a5e82c0dULL
};

static u64 curve_g_y[NDIGITS] = {
  0xaf268adb32322e5cULL, 0x5fde0b5344766740ULL,
  0x895786c4bb46e956ULL, 0x32879423ab1a0375ULL
};

static u64 curve_p[NDIGITS] = {
  0xfffffffffffffd97ULL, 0xffffffffffffffffULL,
  0xffffffffffffffffULL, 0xffffffffffffffffULL
};

static u64 curve_n[NDIGITS] = {
  0xc115af556c360c67ULL, 0x0fd8cddfc87b6635ULL,
  0x0000000000000000ULL, 0x4000000000000000ULL
};

static u64 curve_a[NDIGITS] = {
  0xb22c656f277e7335ULL, 0xe25e2013bf95aa33ULL,
  0xaf4892c23035a27cULL, 0xc2173f1513981673ULL
};

static u64 curve_b[NDIGITS] = {
  0xba9337a6f8ae9513ULL, 0x22fccd9108e17bf7ULL,
  0xcc20e7c359a9d41aULL, 0x295f9bae7428ed9cULL
};

static struct ecc_curve curve = {
  .name = "gost_tc256a",
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

int gost3410_256tc26a_public(
    uint8_t public_key[GOST3410_256_PUBLIC_SIZE],
    const uint8_t private_key[GOST3410_256_KEY_SIZE])
{
  u64 d[NDIGITS];
  u64 x[NDIGITS];
  u64 y[NDIGITS];
  struct ecc_point q = ECC_POINT_INIT(x, y, NDIGITS);

  vli_from_le64(d, private_key, NDIGITS);
  if (!scalar_valid(d))
    return -1;

  ecc_point_mult_generic(&q, &curve.g, d, &curve);
  vli_to_le(public_key, q.x);
  vli_to_le(public_key + GOST3410_256_KEY_SIZE, q.y);
  memset(d, 0, sizeof(d));
  return 0;
}

int gost3410_256tc26a_sign(
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

  vli_from_le64(d, private_key, NDIGITS);
  vli_from_le64(k, nonce, NDIGITS);
  if (!scalar_valid(d) || !scalar_valid(k))
    return -1;

  digest_scalar(e, digest);
  ecc_point_mult_generic(&c, &curve.g, k, &curve);
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

int gost3410_256tc26a_verify(
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
  u64 px[NDIGITS];
  u64 py[NDIGITS];
  u64 qx2[NDIGITS];
  u64 qy2[NDIGITS];
  struct ecc_point q = ECC_POINT_INIT(qx, qy, NDIGITS);
  struct ecc_point c = ECC_POINT_INIT(cx, cy, NDIGITS);
  int inf;

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
  (void) px;
  (void) py;
  (void) qx2;
  (void) qy2;
  (void) inf;
  ecc_point_mult_shamir(&c, z1, &curve.g, z2, &q, &curve);
  if (vli_cmp(c.x, curve.n, NDIGITS) >= 0)
    vli_sub(c.x, c.x, curve.n, NDIGITS);
  return vli_cmp(c.x, r, NDIGITS) == 0 ? 0 : -1;
}

int gost3410_256tc26a_vko(
    uint8_t shared_key[GOST3410_256_DIGEST_SIZE],
    const uint8_t public_key[GOST3410_256_PUBLIC_SIZE],
    const uint8_t private_key[GOST3410_256_KEY_SIZE],
    const uint8_t ukm[GOST3410_256_KEY_SIZE / 2])
{
  u64 qx[NDIGITS];
  u64 qy[NDIGITS];
  u64 d[NDIGITS];
  u64 u[NDIGITS] = { 0 };
  u64 scalar[NDIGITS];
  u64 x[NDIGITS];
  u64 y[NDIGITS];
  uint8_t secret[GOST3410_256_PUBLIC_SIZE];
  struct ecc_point q = ECC_POINT_INIT(qx, qy, NDIGITS);

  vli_from_le64(qx, public_key, NDIGITS);
  vli_from_le64(qy, public_key + GOST3410_256_KEY_SIZE, NDIGITS);
  vli_from_le64(d, private_key, NDIGITS);
  memcpy(u, ukm, GOST3410_256_KEY_SIZE / 2);
  if (!ecc_point_valid_generic(&curve, &q) ||
      !scalar_valid(d) || vli_is_zero(u, NDIGITS))
    return -1;

  vli_mod_mult_slow(scalar, d, u, curve.n, NDIGITS);
  if (vli_is_zero(scalar, NDIGITS))
    return -1;
  ecc_point_mult_generic(&q, &q, scalar, &curve);
  memcpy(x, q.x, sizeof(x));
  memcpy(y, q.y, sizeof(y));
  vli_to_le(secret, x);
  vli_to_le(secret + GOST3410_256_KEY_SIZE, y);
  streebog256(shared_key, secret, sizeof(secret));
  memset(d, 0, sizeof(d));
  memset(scalar, 0, sizeof(scalar));
  memset(secret, 0, sizeof(secret));
  return 0;
}
