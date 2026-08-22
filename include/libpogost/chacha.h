/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LIBPOGOST_CHACHA_H
#define LIBPOGOST_CHACHA_H

#include <libpogost/types.h>

#define POGOST_CHACHA_IV_SIZE 16
#define POGOST_CHACHA_KEY_SIZE 32
#define POGOST_CHACHA_BLOCK_SIZE 64
#define POGOST_CHACHAPOLY_IV_SIZE 12
#define POGOST_CHACHA_KEY_WORDS 8
#define POGOST_CHACHA_STATE_WORDS 16
#define POGOST_HCHACHA_OUT_WORDS 8
#define POGOST_XCHACHA_IV_SIZE 32
#define POGOST_CHACHA_CONSTANT_EXPA 0x61707865U
#define POGOST_CHACHA_CONSTANT_ND_3 0x3320646eU
#define POGOST_CHACHA_CONSTANT_2_BY 0x79622d32U
#define POGOST_CHACHA_CONSTANT_TE_K 0x6b206574U

struct pogost_chacha_state {
	u32 x[POGOST_CHACHA_STATE_WORDS];
};

void pogost_chacha_block_generic(struct pogost_chacha_state *state,
				 u8 out[POGOST_CHACHA_BLOCK_SIZE], int nrounds);
void pogost_hchacha_block_generic(const struct pogost_chacha_state *state,
				  u32 out[POGOST_HCHACHA_OUT_WORDS], int nrounds);
void pogost_chacha_crypt(struct pogost_chacha_state *state, u8 *dst,
			 const u8 *src, unsigned int bytes, int nrounds);
void pogost_hchacha_block(const struct pogost_chacha_state *state,
			  u32 out[POGOST_HCHACHA_OUT_WORDS], int nrounds);
void pogost_chacha_init(struct pogost_chacha_state *state, const u32 *key,
			const u8 *iv);
void pogost_chacha20_crypt(struct pogost_chacha_state *state, u8 *dst,
			   const u8 *src, unsigned int bytes);
void pogost_chacha_zeroize_state(struct pogost_chacha_state *state);

#endif
