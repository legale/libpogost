#include "pfx_internal.h"

#include <stdio.h>
#include <string.h>

static const uint8_t pass_utf16le[] = {
  '1', 0, '2', 0, '3', 0, '4', 0, '5', 0, '6', 0,
};

static const uint8_t salt[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t kdf_expected[32] = {
  0x99, 0xa5, 0xcb, 0xd1, 0x95, 0x79, 0x95, 0x9b,
  0xc3, 0x61, 0xad, 0x2b, 0x1b, 0xfd, 0x81, 0x8f,
  0x7b, 0x9e, 0x26, 0x71, 0xfb, 0xcc, 0xab, 0x03,
  0x15, 0xe2, 0x0a, 0xc4, 0xa0, 0x1e, 0x02, 0x01,
};

static const uint8_t ukm[8] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};

static const uint8_t wrap_expected[32] = {
  0x3e, 0xae, 0x7a, 0x87, 0xe6, 0x8a, 0xb6, 0xf2,
  0xb6, 0x35, 0x71, 0xa1, 0x5c, 0x31, 0x48, 0x46,
  0x90, 0xef, 0x98, 0x68, 0x79, 0x40, 0x3c, 0x58,
  0xa8, 0x0b, 0xfb, 0x6d, 0x0a, 0xb9, 0x17, 0xf5,
};

int main(void)
{
  uint8_t raw[32];
  uint8_t wrapped[32];
  uint8_t unwrapped[32];
  uint8_t blob[37];
  uint8_t enc[sizeof(blob)];
  uint8_t dec[sizeof(blob)];
  uint8_t key[32];
  size_t i;

  if (cryptopro_keybag_kdf(key, pass_utf16le, sizeof(pass_utf16le),
                           salt, sizeof(salt), 2000) ||
      memcmp(key, kdf_expected, sizeof(key))) {
    fprintf(stderr, "cryptopro keybag kdf failed\n");
    return 1;
  }

  for (i = 0; i < sizeof(raw); i++) {
    raw[i] = i;
  }
  if (cryptopro_keybag_wrap(wrapped, raw, sizeof(raw), key,
                            ukm, sizeof(ukm), 1) ||
      memcmp(wrapped, wrap_expected, sizeof(wrapped))) {
    fprintf(stderr, "cryptopro keybag wrap failed\n");
    return 1;
  }
  if (cryptopro_keybag_wrap(unwrapped, wrapped, sizeof(wrapped), key,
                            ukm, sizeof(ukm), 0) ||
      memcmp(unwrapped, raw, sizeof(raw))) {
    fprintf(stderr, "cryptopro keybag unwrap failed\n");
    return 1;
  }

  for (i = 0; i < sizeof(blob); i++) {
    blob[i] = i * 3;
  }
  if (cryptopro_keybag_blob_crypt(enc, blob, sizeof(blob), key,
                                  salt, sizeof(salt), 1) ||
      cryptopro_keybag_blob_crypt(dec, enc, sizeof(enc), key,
                                  salt, sizeof(salt), 0) ||
      memcmp(dec, blob, sizeof(blob))) {
    fprintf(stderr, "cryptopro keybag blob cfb failed\n");
    return 1;
  }

  puts("cryptopro keybag: ok");
  return 0;
}
