/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LIBPOGOST_PFX_INTERNAL_H
#define LIBPOGOST_PFX_INTERNAL_H

#include <stddef.h>
#include <libpogost/types.h>

int pfx_mac_streebog512(u8 out[64],
                         const u8 *data, size_t data_len,
                         const u8 *pass, size_t pass_len,
                         const u8 *salt, size_t salt_len, u32 iter);
int cryptopro_keybag_kdf(u8 out[32],
                         const u8 *pass_utf16le, size_t pass_len,
                         const u8 *salt, size_t salt_len, u32 iter);
int cryptopro_keybag_wrap(u8 *out, u8 mac[4],
                          const u8 *in, size_t len,
                          const u8 key[32],
                          const u8 *ukm, size_t ukm_len, int enc);
int cryptopro_keybag_blob_crypt(u8 *out, const u8 *in, size_t len,
                                const u8 key[32],
                                const u8 *salt, size_t salt_len, int enc);

#endif
