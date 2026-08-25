CC ?= musl-gcc
SAN_CC ?= cc
AR ?= ar
BUILD_DIR ?= build
# Основная сборка должна работать с musl. Санитайзеры задают свой CC.
CPPFLAGS ?= -Iinclude -Isrc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror

LIB = libpogost.a
LIB_OBJS = $(BUILD_DIR)/kuznyechik.o \
	$(BUILD_DIR)/generic/cryptopro_keybag_generic.o \
	$(BUILD_DIR)/generic/gost28147_generic.o \
	$(BUILD_DIR)/generic/ecc_generic.o \
	$(BUILD_DIR)/generic/gost3410_256_generic.o \
	$(BUILD_DIR)/generic/gost3410_256_tc26_generic.o \
	$(BUILD_DIR)/generic/gost3410_generic.o \
	$(BUILD_DIR)/generic/gost3411_94_generic.o \
	$(BUILD_DIR)/generic/gost_tls_generic.o \
	$(BUILD_DIR)/generic/hmac_streebog_generic.o \
	$(BUILD_DIR)/generic/kuznyechik_generic.o \
	$(BUILD_DIR)/generic/pbkdf2_generic.o \
	$(BUILD_DIR)/generic/pfx_generic.o \
	$(BUILD_DIR)/generic/streebog_generic.o \
	$(BUILD_DIR)/optimized/gost3410_256a.o

ifeq ($(shell uname -m),x86_64)
CPPFLAGS += -DLIBPOGOST_HAVE_KUZNYECHIK_SIMD=1
LIB_OBJS += $(BUILD_DIR)/x86_64/kuznyechik_simd.o \
	$(BUILD_DIR)/x86_64/kuznyechik_simd_x86_64.o
endif
TESTS = $(BUILD_DIR)/test_gost28147 $(BUILD_DIR)/test_gost3410 \
	$(BUILD_DIR)/test_gost3411_94 $(BUILD_DIR)/test_gost_tls \
	$(BUILD_DIR)/test_hmac_streebog $(BUILD_DIR)/test_pbkdf2 \
	$(BUILD_DIR)/test_cryptopro_keybag \
	$(BUILD_DIR)/test_pfx \
	$(BUILD_DIR)/test_kuznyechik \
	$(BUILD_DIR)/test_streebog

.PHONY: all static test san clean

all: $(LIB)

static: $(LIB)

$(LIB): $(LIB_OBJS)
	$(AR) rcs $@ $^

$(BUILD_DIR)/%.o: src/%.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/generic/%.o: src/generic/%.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: src/%.S
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/test_%: tests/test_%.c $(LIB)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) -o $@

test: $(TESTS)
	@for test in $(TESTS); do $$test || exit; done

san:
	$(MAKE) BUILD_DIR=build/san-asan LIB=build/san-asan/libpogost.a \
		CC="$(SAN_CC)" \
		CFLAGS="$(CFLAGS) -fsanitize=address -fno-omit-frame-pointer" test
	$(MAKE) BUILD_DIR=build/san-ubsan LIB=build/san-ubsan/libpogost.a \
		CC="$(SAN_CC)" \
		CFLAGS="$(CFLAGS) -fsanitize=undefined" test

clean:
	rm -rf build $(LIB)
