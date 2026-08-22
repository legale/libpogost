/* SPDX-License-Identifier: GPL-2.0 */
#include "../kernel_compat.h"


void pogost_chacha_init(struct pogost_chacha_state *state, const u32 *key,
			const u8 *iv)
{
	state->x[0] = POGOST_CHACHA_CONSTANT_EXPA; state->x[1] = POGOST_CHACHA_CONSTANT_ND_3;
	state->x[2] = POGOST_CHACHA_CONSTANT_2_BY; state->x[3] = POGOST_CHACHA_CONSTANT_TE_K;
	state->x[4] = key[0]; state->x[5] = key[1];
	state->x[6] = key[2]; state->x[7] = key[3];
	state->x[8] = key[4]; state->x[9] = key[5];
	state->x[10] = key[6]; state->x[11] = key[7];
	state->x[12] = get_unaligned_le32(iv + 0);
	state->x[13] = get_unaligned_le32(iv + 4);
	state->x[14] = get_unaligned_le32(iv + 8);
	state->x[15] = get_unaligned_le32(iv + 12);
}

void pogost_chacha20_crypt(struct pogost_chacha_state *state, u8 *dst,
			   const u8 *src, unsigned int bytes)
{
	pogost_chacha_crypt(state, dst, src, bytes, 20);
}

void pogost_chacha_zeroize_state(struct pogost_chacha_state *state)
{
	memzero_explicit(state, sizeof(*state));
}
