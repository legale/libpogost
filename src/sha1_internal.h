/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LIBPOGOST_SHA1_INTERNAL_H
#define LIBPOGOST_SHA1_INTERNAL_H

#include <libpogost/types.h>

struct sha1_ctx {
  u32 h[5];
  u64 bits;
  u8 block[64];
  size_t used;
};

void sha1_init(struct sha1_ctx *ctx);
void sha1_update(struct sha1_ctx *ctx, const u8 *data, size_t len);
void sha1_final(struct sha1_ctx *ctx, u8 out[20]);

#endif
