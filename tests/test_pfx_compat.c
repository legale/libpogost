#include <libpogost/pfx.h>

#include <stdio.h>
#include <string.h>

#define PFX_PATH "../pki-wnam2/client-cpro.pfx"
#define PFX_SIZE 2692
#define AUTH_OFF 30
#define AUTH_LEN 2564
#define MAC_OFF 2614
#define SALT_OFF 2680
#define SALT_LEN 8
#define ITER 2048

static const u8 auth_hdr[] = { 0x30, 0x82, 0x0a, 0x00 };
static const u8 mac_expected[64] = {
  0xdb, 0x17, 0x07, 0xc2, 0x7d, 0x57, 0xbf, 0xb6,
  0x19, 0xbf, 0x2c, 0x2b, 0x26, 0xa9, 0x6d, 0xed,
  0xbb, 0x61, 0x4e, 0xcd, 0x04, 0x0e, 0x1e, 0x7a,
  0xcf, 0xf5, 0x7b, 0x1d, 0x97, 0x2b, 0xb1, 0xa2,
  0xd2, 0xd4, 0x59, 0x19, 0x21, 0x70, 0x0c, 0xe0,
  0x73, 0x5a, 0x65, 0xfd, 0xa1, 0x59, 0x80, 0xc4,
  0xc9, 0x49, 0x83, 0xd8, 0x86, 0x40, 0x9f, 0x39,
  0xe6, 0x9f, 0x54, 0x5b, 0x72, 0x45, 0x92, 0xf6,
};

int main(void)
{
  static const u8 pass[] = "123456";
  u8 pfx[PFX_SIZE];
  u8 mac[GOST_PFX_MAC_SIZE];
  FILE *f;

  f = fopen(PFX_PATH, "rb");
  if (!f) {
    fprintf(stderr, "pfx compat: open failed\n");
    return 1;
  }
  if (fread(pfx, 1, sizeof(pfx), f) != sizeof(pfx) || fgetc(f) != EOF) {
    fclose(f);
    fprintf(stderr, "pfx compat: fixture size changed\n");
    return 1;
  }
  fclose(f);

  if (memcmp(pfx + AUTH_OFF, auth_hdr, sizeof(auth_hdr)) ||
      memcmp(pfx + MAC_OFF, mac_expected, sizeof(mac_expected))) {
    fprintf(stderr, "pfx compat: fixture layout changed\n");
    return 1;
  }

  if (gost_pfx_mac(mac, pfx + AUTH_OFF, AUTH_LEN,
                   pass, sizeof(pass) - 1, pfx + SALT_OFF, SALT_LEN, ITER) ||
      memcmp(mac, mac_expected, sizeof(mac_expected))) {
    fprintf(stderr, "pfx compat: CryptoPro MAC mismatch\n");
    return 1;
  }

  puts("pfx compat: ok");
  return 0;
}
