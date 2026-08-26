#ifndef LIBPOGOST_TYPES_H
#define LIBPOGOST_TYPES_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#include <stddef.h>
typedef __UINT8_TYPE__ u8;
typedef __UINT16_TYPE__ u16;
typedef __UINT32_TYPE__ u32;
typedef __UINT64_TYPE__ u64;
typedef __INT8_TYPE__ s8;
typedef __INT16_TYPE__ s16;
typedef __INT32_TYPE__ s32;
typedef __INT64_TYPE__ s64;
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
