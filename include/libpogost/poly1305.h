/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LIBPOGOST_POLY1305_H
#define LIBPOGOST_POLY1305_H

#include <libpogost/types.h>

#define POGOST_POLY1305_BLOCK_SIZE 16
#define POGOST_POLY1305_KEY_SIZE 32
#define POGOST_POLY1305_DIGEST_SIZE 16

struct pogost_poly1305_key {
	union { u32 r[5]; u64 r64[3]; };
};

struct pogost_poly1305_core_key {
	struct pogost_poly1305_key key;
	struct pogost_poly1305_key precomputed_s;
};

struct pogost_poly1305_state {
	union { u32 h[5]; u64 h64[3]; };
};

struct pogost_poly1305_block_state {
	struct pogost_poly1305_state h;
	union {
		struct pogost_poly1305_key opaque_r[11];
		struct pogost_poly1305_core_key core_r;
	};
};

struct pogost_poly1305_desc_ctx {
	u8 buf[POGOST_POLY1305_BLOCK_SIZE];
	unsigned int buflen;
	u32 s[4];
	struct pogost_poly1305_block_state state;
};

void pogost_poly1305_core_setkey(struct pogost_poly1305_core_key *key,
				 const u8 raw_key[POGOST_POLY1305_BLOCK_SIZE]);
void pogost_poly1305_core_blocks(struct pogost_poly1305_state *state,
				 const struct pogost_poly1305_core_key *key,
				 const void *src, unsigned int nblocks, u32 hibit);
void pogost_poly1305_core_emit(const struct pogost_poly1305_state *state,
			       const u32 nonce[4], void *dst);
void pogost_poly1305_init(struct pogost_poly1305_desc_ctx *desc,
			  const u8 key[POGOST_POLY1305_KEY_SIZE]);
void pogost_poly1305_update(struct pogost_poly1305_desc_ctx *desc,
			    const u8 *src, unsigned int nbytes);
void pogost_poly1305_final(struct pogost_poly1305_desc_ctx *desc, u8 *digest);

#endif
