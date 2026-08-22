/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LIBPOGOST_POLY1305_INTERNAL_H
#define LIBPOGOST_POLY1305_INTERNAL_H
#include "kernel_compat.h"

static inline void poly1305_core_init(struct poly1305_state *state)
{
	*state = (struct poly1305_state){};
}

static inline void poly1305_block_init_generic(struct poly1305_block_state *desc,
					       const u8 raw_key[POLY1305_BLOCK_SIZE])
{
	poly1305_core_init(&desc->h);
	poly1305_core_setkey(&desc->core_r, raw_key);
}

static inline void poly1305_blocks_generic(struct poly1305_block_state *state,
					   const u8 *src, unsigned int len,
					   u32 padbit)
{
	poly1305_core_blocks(&state->h, &state->core_r, src,
			     len / POLY1305_BLOCK_SIZE, padbit);
}

static inline void poly1305_emit_generic(const struct poly1305_state *state,
					 u8 digest[POLY1305_DIGEST_SIZE],
					 const u32 nonce[4])
{
	poly1305_core_emit(state, nonce, digest);
}
#endif
