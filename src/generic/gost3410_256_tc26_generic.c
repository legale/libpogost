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


static void mod_sub(u64 *out, const u64 *a, const u64 *b)
{
  u64 t[NDIGITS];

  if (vli_cmp(a, b, NDIGITS) >= 0) {
    vli_sub(out, a, b, NDIGITS);
    return;
  }

  vli_sub(t, b, a, NDIGITS);
  vli_sub(out, curve.p, t, NDIGITS);
}

static int point_inf(const struct ecc_point *p)
{
  return vli_is_zero(p->x, NDIGITS) && vli_is_zero(p->y, NDIGITS);
}

static void point_copy(struct ecc_point *out, const struct ecc_point *p)
{
  memcpy(out->x, p->x, NDIGITS * sizeof(*out->x));
  memcpy(out->y, p->y, NDIGITS * sizeof(*out->y));
}

static void point_zero(struct ecc_point *p)
{
  memset(p->x, 0, NDIGITS * sizeof(*p->x));
  memset(p->y, 0, NDIGITS * sizeof(*p->y));
}

static void point_double(struct ecc_point *out, const struct ecc_point *p)
{
  u64 x[NDIGITS];
  u64 y[NDIGITS];
  u64 num[NDIGITS];
  u64 den[NDIGITS];
  u64 inv[NDIGITS];
  u64 l[NDIGITS];
  u64 t[NDIGITS];
  u64 x3[NDIGITS];
  u64 y3[NDIGITS];

  if (point_inf(p) || vli_is_zero(p->y, NDIGITS)) {
    point_zero(out);
    return;
  }

  memcpy(x, p->x, sizeof(x));
  memcpy(y, p->y, sizeof(y));

  vli_mod_mult_slow(t, x, x, curve.p, NDIGITS);
  vli_mod_add_generic(num, t, t, curve.p, NDIGITS);
  vli_mod_add_generic(num, num, t, curve.p, NDIGITS);
  vli_mod_add_generic(num, num, curve.a, curve.p, NDIGITS);
  vli_mod_add_generic(den, y, y, curve.p, NDIGITS);
  vli_mod_inv(inv, den, curve.p, NDIGITS);
  vli_mod_mult_slow(l, num, inv, curve.p, NDIGITS);

  vli_mod_mult_slow(x3, l, l, curve.p, NDIGITS);
  vli_mod_add_generic(t, x, x, curve.p, NDIGITS);
  mod_sub(x3, x3, t);
  mod_sub(t, x, x3);
  vli_mod_mult_slow(y3, l, t, curve.p, NDIGITS);
  mod_sub(y3, y3, y);

  memcpy(out->x, x3, sizeof(x3));
  memcpy(out->y, y3, sizeof(y3));
}

static void point_add(struct ecc_point *out, const struct ecc_point *p,
                      const struct ecc_point *q)
{
  u64 x1[NDIGITS];
  u64 y1[NDIGITS];
  u64 x2[NDIGITS];
  u64 y2[NDIGITS];
  u64 num[NDIGITS];
  u64 den[NDIGITS];
  u64 inv[NDIGITS];
  u64 l[NDIGITS];
  u64 t[NDIGITS];
  u64 x3[NDIGITS];
  u64 y3[NDIGITS];
  struct ecc_point a = ECC_POINT_INIT(x1, y1, NDIGITS);

  if (point_inf(p)) {
    point_copy(out, q);
    return;
  }
  if (point_inf(q)) {
    point_copy(out, p);
    return;
  }
  if (vli_cmp(p->x, q->x, NDIGITS) == 0) {
    if (vli_cmp(p->y, q->y, NDIGITS) == 0) {
      point_double(out, p);
      return;
    }
    point_zero(out);
    return;
  }

  memcpy(x1, p->x, sizeof(x1));
  memcpy(y1, p->y, sizeof(y1));
  memcpy(x2, q->x, sizeof(x2));
  memcpy(y2, q->y, sizeof(y2));

  mod_sub(num, y2, y1);
  mod_sub(den, x2, x1);
  vli_mod_inv(inv, den, curve.p, NDIGITS);
  vli_mod_mult_slow(l, num, inv, curve.p, NDIGITS);

  vli_mod_mult_slow(x3, l, l, curve.p, NDIGITS);
  mod_sub(x3, x3, x1);
  mod_sub(x3, x3, x2);
  mod_sub(t, x1, x3);
  vli_mod_mult_slow(y3, l, t, curve.p, NDIGITS);
  mod_sub(y3, y3, y1);

  memcpy(a.x, x3, sizeof(x3));
  memcpy(a.y, y3, sizeof(y3));
  point_copy(out, &a);
}

static void point_mult(struct ecc_point *out, const struct ecc_point *p,
                       const u64 *k)
{
  u64 rx[NDIGITS] = { 0 };
  u64 ry[NDIGITS] = { 0 };
  u64 tx[NDIGITS];
  u64 ty[NDIGITS];
  struct ecc_point r = ECC_POINT_INIT(rx, ry, NDIGITS);
  struct ecc_point t = ECC_POINT_INIT(tx, ty, NDIGITS);
  unsigned int bits;
  int i;

  point_copy(&t, p);
  bits = vli_num_bits(k, NDIGITS);
  for (i = (int)bits - 1; i >= 0; i--) {
    point_double(&r, &r);
    if (k[i / 64] & ((u64)1 << (i % 64)))
      point_add(&r, &r, &t);
  }
  point_copy(out, &r);
}

static int scalar_valid(const u64 *scalar)
{
  return !vli_is_zero(scalar, NDIGITS) &&
         vli_cmp(scalar, curve.n, NDIGITS) < 0;
}

static void scalar_reduce(u64 *v)
{
  while (vli_cmp(v, curve.n, NDIGITS) >= 0)
    vli_sub(v, v, curve.n, NDIGITS);
}

static void digest_scalar(u64 *e, const uint8_t *digest)
{
  vli_from_le64(e, digest, NDIGITS);
  scalar_reduce(e);
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

  point_mult(&q, &curve.g, d);
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
  point_mult(&c, &curve.g, k);
  memcpy(r, c.x, sizeof(r));
  scalar_reduce(r);
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
  {
    struct ecc_point p1 = ECC_POINT_INIT(px, py, NDIGITS);
    struct ecc_point p2 = ECC_POINT_INIT(qx2, qy2, NDIGITS);

    point_mult(&p1, &curve.g, z1);
    point_mult(&p2, &q, z2);
    point_add(&c, &p1, &p2);
  }
  scalar_reduce(c.x);
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
  u64 h[NDIGITS] = { 4 };
  u64 t[NDIGITS];
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

  vli_mod_mult_slow(t, d, u, curve.n, NDIGITS);
  vli_mod_mult_slow(scalar, t, h, curve.n, NDIGITS);
  if (vli_is_zero(scalar, NDIGITS))
    return -1;
  point_mult(&q, &q, scalar);
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
