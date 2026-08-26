#ifndef LIBPOGOST_TYPES_H
#define LIBPOGOST_TYPES_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#include <stddef.h>
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long long s64;
#ifdef __SIZEOF_INT128__
typedef unsigned __int128 u128;
#endif
#endif

#ifndef UINT8_C
#define UINT8_C(x) x##U
#endif
#ifndef UINT16_C
#define UINT16_C(x) x##U
#endif
#ifndef UINT32_C
#define UINT32_C(x) x##U
#endif
#ifndef UINT64_C
#define UINT64_C(x) x##ULL
#endif
#ifndef UINT32_MAX
#define UINT32_MAX 0xffffffffU
#endif

#endif
