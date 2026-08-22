#ifndef LIBPOGOST_MEMORY_H
#define LIBPOGOST_MEMORY_H

#include <libpogost/types.h>

void pogost_memzero(void *p, size_t len);
bool pogost_memeq(const void *a, const void *b, size_t len);

#endif
