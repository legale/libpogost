/* SPDX-License-Identifier: Apache-2.0 */
#include "hmac_streebog_internal.h"
#include "pbkdf2_internal.h"
#include "pfx_internal.h"

#include <string.h>

static void memzero(void *ptr, size_t len)
{
  volatile uint8_t *p = ptr;

  while (len--) {
    *p++ = 0;
  }
}

int pfx_mac_streebog512(uint8_t out[64],
                         const uint8_t *data, size_t data_len,
                         const uint8_t *pass, size_t pass_len,
                         const uint8_t *salt, size_t salt_len, uint32_t iter)
{
  uint8_t dk[96];

  if (!out || (!data && data_len) || (!pass && pass_len) ||
      (!salt && salt_len) || !iter) {
    return -1;
  }
  if (pbkdf2_streebog512(dk, sizeof(dk), pass, pass_len, salt, salt_len,
                         iter)) {
    return -1;
  }
  hmac_streebog512(out, dk + 64, 32, data, data_len);
  memzero(dk, sizeof(dk));
  return 0;
}
