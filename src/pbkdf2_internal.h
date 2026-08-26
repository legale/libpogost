/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LIBPOGOST_PBKDF2_INTERNAL_H
#define LIBPOGOST_PBKDF2_INTERNAL_H

#include <stddef.h>
#include <libpogost/types.h>

int pbkdf2_streebog512(u8 *out, size_t out_len,
                       const u8 *pass, size_t pass_len,
                       const u8 *salt, size_t salt_len, u32 iter);

#endif
