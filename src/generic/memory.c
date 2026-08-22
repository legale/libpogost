#include <libpogost/memory.h>

#ifdef __KERNEL__
#include <crypto/utils.h>
#include <linux/string.h>

void pogost_memzero(void *p, size_t len)
{
	memzero_explicit(p, len);
}

bool pogost_memeq(const void *a, const void *b, size_t len)
{
	return !crypto_memneq(a, b, len);
}
#else
void pogost_memzero(void *p, size_t len)
{
	volatile u8 *q = p;

	while (len--)
		*q++ = 0;
}

bool pogost_memeq(const void *a, const void *b, size_t len)
{
	const u8 *x = a;
	const u8 *y = b;
	u8 d = 0;

	while (len--)
		d |= *x++ ^ *y++;
	return d == 0;
}
#endif
