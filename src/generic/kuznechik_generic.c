/*
 * ГОСТ Р 34.12-2015 (Kuznechik), generic-реализация.
 *
 * Copyright (c) 2018 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <stdint.h>

#include <libpogost/kuznechik.h>

#include "../kuznechik_internal.h"

#include "kuztable.h"

/* S-преобразование заменяет каждый байт таблицей подстановки. */
static void s_transform(uint8_t *a, const uint8_t *b)
{
	a[0] = pi[b[0]];
	a[1] = pi[b[1]];
	a[2] = pi[b[2]];
	a[3] = pi[b[3]];
	a[4] = pi[b[4]];
	a[5] = pi[b[5]];
	a[6] = pi[b[6]];
	a[7] = pi[b[7]];
	a[8] = pi[b[8]];
	a[9] = pi[b[9]];
	a[10] = pi[b[10]];
	a[11] = pi[b[11]];
	a[12] = pi[b[12]];
	a[13] = pi[b[13]];
	a[14] = pi[b[14]];
	a[15] = pi[b[15]];
}

static void sinv_transform(uint8_t *a, const uint8_t *b)
{
	a[0] = pi_inv[b[0]];
	a[1] = pi_inv[b[1]];
	a[2] = pi_inv[b[2]];
	a[3] = pi_inv[b[3]];
	a[4] = pi_inv[b[4]];
	a[5] = pi_inv[b[5]];
	a[6] = pi_inv[b[6]];
	a[7] = pi_inv[b[7]];
	a[8] = pi_inv[b[8]];
	a[9] = pi_inv[b[9]];
	a[10] = pi_inv[b[10]];
	a[11] = pi_inv[b[11]];
	a[12] = pi_inv[b[12]];
	a[13] = pi_inv[b[13]];
	a[14] = pi_inv[b[14]];
	a[15] = pi_inv[b[15]];
}

static void linv_transform(uint8_t *a, const uint8_t *b)
{
	kuznechik_copy(a, &kuz_table_inv[0][b[0] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[1][b[1] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[2][b[2] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[3][b[3] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[4][b[4] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[5][b[5] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[6][b[6] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[7][b[7] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[8][b[8] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[9][b[9] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[10][b[10] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[11][b[11] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[12][b[12] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[13][b[13] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[14][b[14] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(a, &kuz_table_inv[15][b[15] * 16], KUZNECHIK_BLOCK_SIZE);
}

static void lsx_transform(uint8_t *a, const uint8_t *b, const uint8_t *c)
{
	uint8_t t[16];

	kuznechik_copy(t, &kuz_table[0][(b[0] ^ c[0]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table[1][(b[1] ^ c[1]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table[2][(b[2] ^ c[2]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table[3][(b[3] ^ c[3]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table[4][(b[4] ^ c[4]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table[5][(b[5] ^ c[5]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table[6][(b[6] ^ c[6]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table[7][(b[7] ^ c[7]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table[8][(b[8] ^ c[8]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table[9][(b[9] ^ c[9]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table[10][(b[10] ^ c[10]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table[11][(b[11] ^ c[11]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table[12][(b[12] ^ c[12]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table[13][(b[13] ^ c[13]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table[14][(b[14] ^ c[14]) * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor_copy(a, t, &kuz_table[15][(b[15] ^ c[15]) * 16], KUZNECHIK_BLOCK_SIZE);
}

static void xli_si(uint8_t *a, const uint8_t *b, const uint8_t *c)
{
	uint8_t t[16];

	kuznechik_copy(t, &kuz_table_inv_LS[0][b[0] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[1][b[1] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[2][b[2] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[3][b[3] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[4][b[4] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[5][b[5] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[6][b[6] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[7][b[7] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[8][b[8] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[9][b[9] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[10][b[10] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[11][b[11] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[12][b[12] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[13][b[13] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[14][b[14] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor(t, &kuz_table_inv_LS[15][b[15] * 16], KUZNECHIK_BLOCK_SIZE);
	kuznechik_xor_copy(a, t, c, 16);
}

static void subkey(uint8_t *out, const uint8_t *key, unsigned int i)
{
	uint8_t test[16];

	lsx_transform(test, key+0, kuz_key_table[i + 0]);
	kuznechik_xor_copy(out+16, test, key + 16, 16);
	lsx_transform(test, out+16, kuz_key_table[i + 1]);
	kuznechik_xor_copy(out+0, test, key + 0, 16);
	lsx_transform(test, out+0, kuz_key_table[i + 2]);
	kuznechik_xor(out+16, test, 16);
	lsx_transform(test, out+16, kuz_key_table[i + 3]);
	kuznechik_xor(out+0, test, 16);
	lsx_transform(test, out+0, kuz_key_table[i + 4]);
	kuznechik_xor(out+16, test, 16);
	lsx_transform(test, out+16, kuz_key_table[i + 5]);
	kuznechik_xor(out+0, test, 16);
	lsx_transform(test, out+0, kuz_key_table[i + 6]);
	kuznechik_xor(out+16, test, 16);
	lsx_transform(test, out+16, kuz_key_table[i + 7]);
	kuznechik_xor(out+0, test, 16);
}

/* Разворачиваем пользовательский ключ в десять раундовых ключей. */
int kuznechik_generic_setkey(struct kuznechik_ctx *ctx,
                             const uint8_t key[KUZNECHIK_KEY_SIZE])
{
	struct kuznechik_state *state;
	unsigned int i;

	if (!ctx || !key)
		return -1;
	state = kuznechik_state(ctx);

	kuznechik_copy(state->key, key, KUZNECHIK_KEY_SIZE);
	subkey(state->key + 32, state->key, 0);
	subkey(state->key + 64, state->key + 32, 8);
	subkey(state->key + 96, state->key + 64, 16);
	subkey(state->key + 128, state->key + 96, 24);
	for (i = 0; i < 10; i++)
		linv_transform(state->dekey + 16 * i, state->key + 16 * i);

	return 0;
}

void kuznechik_generic_encrypt(const struct kuznechik_ctx *ctx,
                               uint8_t out[KUZNECHIK_BLOCK_SIZE],
                               const uint8_t in[KUZNECHIK_BLOCK_SIZE])
{
	const struct kuznechik_state *state = kuznechik_const_state(ctx);
	uint8_t temp[KUZNECHIK_BLOCK_SIZE];

	lsx_transform(temp, state->key + 16 * 0, in);
	lsx_transform(temp, state->key + 16 * 1, temp);
	lsx_transform(temp, state->key + 16 * 2, temp);
	lsx_transform(temp, state->key + 16 * 3, temp);
	lsx_transform(temp, state->key + 16 * 4, temp);
	lsx_transform(temp, state->key + 16 * 5, temp);
	lsx_transform(temp, state->key + 16 * 6, temp);
	lsx_transform(temp, state->key + 16 * 7, temp);
	lsx_transform(temp, state->key + 16 * 8, temp);
	kuznechik_xor_copy(out, state->key + 16 * 9, temp, 16);
}

void kuznechik_generic_decrypt(const struct kuznechik_ctx *ctx,
                               uint8_t out[KUZNECHIK_BLOCK_SIZE],
                               const uint8_t in[KUZNECHIK_BLOCK_SIZE])
{
	const struct kuznechik_state *state = kuznechik_const_state(ctx);
	uint8_t temp[KUZNECHIK_BLOCK_SIZE];

	s_transform(temp, in);
	xli_si(temp, temp, state->dekey + 16 * 9);
	xli_si(temp, temp, state->dekey + 16 * 8);
	xli_si(temp, temp, state->dekey + 16 * 7);
	xli_si(temp, temp, state->dekey + 16 * 6);
	xli_si(temp, temp, state->dekey + 16 * 5);
	xli_si(temp, temp, state->dekey + 16 * 4);
	xli_si(temp, temp, state->dekey + 16 * 3);
	xli_si(temp, temp, state->dekey + 16 * 2);
	xli_si(temp, temp, state->dekey + 16 * 1);
	sinv_transform(out, temp);
	kuznechik_xor(out, state->key + 16 * 0, 16);
}
