/* SPDX-License-Identifier: MIT */
#ifndef LIBPOGOST_GOST3410_256_INTERNAL_H
#define LIBPOGOST_GOST3410_256_INTERNAL_H

void gost3410_256a_point_mul_two(
    unsigned char outx[32], unsigned char outy[32],
    const unsigned char a[32], const unsigned char b[32],
    const unsigned char inx[32], const unsigned char iny[32]);
void gost3410_256a_point_mul_g(
    unsigned char outx[32], unsigned char outy[32],
    const unsigned char scalar[32]);

#endif
