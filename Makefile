CC ?= musl-gcc
SAN_CC ?= cc
AR ?= ar
BUILD_DIR ?= build
# Основная сборка должна работать с musl. Санитайзеры задают свой CC.
CPPFLAGS ?= -Iinclude -Isrc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror

LIB = libpogost.a
LIB_OBJS = $(BUILD_DIR)/kuznechik.o \
	$(BUILD_DIR)/generic/kuznechik_generic.o
TEST = $(BUILD_DIR)/test_kuznechik

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

$(TEST): tests/test_kuznechik.c $(LIB)
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIB) -o $@

test: $(TEST)
	$(TEST)

san:
	$(MAKE) BUILD_DIR=build/san-asan CC="$(SAN_CC)" \
		CFLAGS="$(CFLAGS) -fsanitize=address -fno-omit-frame-pointer" test
	$(MAKE) BUILD_DIR=build/san-ubsan CC="$(SAN_CC)" \
		CFLAGS="$(CFLAGS) -fsanitize=undefined" test

clean:
	rm -rf build $(LIB)
