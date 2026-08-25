/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LIBPOGOST_PFX_INTERNAL_H
#define LIBPOGOST_PFX_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

int pfx_mac_streebog512(uint8_t out[64],
                         const uint8_t *data, size_t data_len,
                         const uint8_t *pass, size_t pass_len,
                         const uint8_t *salt, size_t salt_len, uint32_t iter);
int cryptopro_keybag_kdf(uint8_t out[32],
                         const uint8_t *pass_utf16le, size_t pass_len,
                         const uint8_t *salt, size_t salt_len, uint32_t iter);
int cryptopro_keybag_wrap(uint8_t *out, uint8_t mac[4],
                          const uint8_t *in, size_t len,
                          const uint8_t key[32],
                          const uint8_t *ukm, size_t ukm_len, int enc);
int cryptopro_keybag_blob_crypt(uint8_t *out, const uint8_t *in, size_t len,
                                const uint8_t key[32],
                                const uint8_t *salt, size_t salt_len, int enc);

#endif
