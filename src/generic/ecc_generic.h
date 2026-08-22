/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-2-Clause */
#ifndef LIBPOGOST_ECC_GENERIC_H
#define LIBPOGOST_ECC_GENERIC_H

#include <libpogost/types.h>

#define ECC_MAX_DIGITS (512 / 64)
#define ECC_POINT_INIT(px, py, digits) \
  (struct ecc_point) { (px), (py), (digits) }


struct ecc_point {
  u64 *x;
  u64 *y;
  unsigned int ndigits;
};

struct ecc_curve {
  const char *name;
  struct ecc_point g;
  u64 *p;
  u64 *n;
  u64 *a;
  u64 *b;
};

bool vli_is_zero(const u64 *vli, unsigned int ndigits);
int vli_cmp(const u64 *left, const u64 *right, unsigned int ndigits);
unsigned int vli_num_bits(const u64 *vli, unsigned int ndigits);
u64 vli_sub(u64 *result, const u64 *left, const u64 *right,
            unsigned int ndigits);
void vli_from_be64(u64 *dest, const void *src, unsigned int ndigits);
void vli_from_le64(u64 *dest, const void *src, unsigned int ndigits);
void vli_mod_mult_slow(u64 *result, const u64 *left, const u64 *right,
                       const u64 *mod, unsigned int ndigits);
void vli_mod_inv(u64 *result, const u64 *input, const u64 *mod,
                 unsigned int ndigits);
void vli_mod_add_generic(u64 *result, const u64 *left, const u64 *right,
                         const u64 *mod, unsigned int ndigits);
void ecc_point_mult_shamir(const struct ecc_point *result,
                           const u64 *u1, const struct ecc_point *p,
                           const u64 *u2, const struct ecc_point *q,
                           const struct ecc_curve *curve);
void ecc_point_mult_generic(struct ecc_point *result,
                            const struct ecc_point *point,
                            const u64 *scalar,
                            const struct ecc_curve *curve);
int ecc_point_valid_generic(const struct ecc_curve *curve,
                            const struct ecc_point *point);

#endif
