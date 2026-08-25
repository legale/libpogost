/* SPDX-License-Identifier: Apache-2.0 */
#include "hmac_streebog_internal.h"
#include "pbkdf2_internal.h"

#include <limits.h>
#include <string.h>

static void memzero(void *ptr, size_t len)
{
  volatile uint8_t *p = ptr;

  while (len--) {
    *p++ = 0;
  }
}

int pbkdf2_streebog512(uint8_t *out, size_t out_len,
                       const uint8_t *pass, size_t pass_len,
                       const uint8_t *salt, size_t salt_len, uint32_t iter)
{
  uint8_t u[64];
  uint8_t t[64];
  uint8_t be[4];
  uint32_t block = 1;
  size_t off = 0;

  if ((!out && out_len) || (!pass && pass_len) || (!salt && salt_len) ||
      !iter) {
    return -1;
  }
  if (out_len > (size_t)UINT32_MAX * sizeof(t)) {
    return -1;
  }

  while (off < out_len) {
    uint32_t i;
    size_t n = out_len - off;
    size_t j;

    be[0] = block >> 24;
    be[1] = block >> 16;
    be[2] = block >> 8;
    be[3] = block;
    hmac_streebog512_parts(u, pass, pass_len, salt, salt_len, be, sizeof(be));
    memcpy(t, u, sizeof(t));
    for (i = 1; i < iter; i++) {
      hmac_streebog512(u, pass, pass_len, u, sizeof(u));
      for (j = 0; j < sizeof(t); j++) {
        t[j] ^= u[j];
      }
    }
    if (n > sizeof(t)) {
      n = sizeof(t);
    }
    memcpy(out + off, t, n);
    off += n;
    block++;
  }

  memzero(u, sizeof(u));
  memzero(t, sizeof(t));
  return 0;
}
