/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LIBPOGOST_PBKDF2_INTERNAL_H
#define LIBPOGOST_PBKDF2_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

int pbkdf2_streebog512(uint8_t *out, size_t out_len,
                       const uint8_t *pass, size_t pass_len,
                       const uint8_t *salt, size_t salt_len, uint32_t iter);

#endif
