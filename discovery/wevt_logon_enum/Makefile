override CC_X64 := x86_64-w64-mingw32-gcc
STRIP_X64 ?= x86_64-w64-mingw32-strip


COMPILER_X64_AVAILABLE := yes
COMPILER_X86_AVAILABLE := no

# Standard BOF compilation flags 
CFLAGS := -Os -std=c99 \
	-fno-stack-protector -fno-stack-check -mno-stack-arg-probe \
	-fno-builtin -fno-builtin-memset -fno-builtin-memcpy -fno-builtin-memmove \
	-ffunction-sections -fdata-sections -nostdlib \
	-fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident \
	-Wall -Wextra -Wno-unused-parameter -Wno-unused-variable \
	-fno-leading-underscore -fno-ms-extensions \
	-Wl,--entry=go \
	-Wl,--no-insert-timestamp \
	-Wl,--exclude-all-symbols \
	-Wl,--dynamicbase,--nxcompat,--no-seh \
	-Wl,--file-alignment=0x1000 \
	-Wl,--image-base=0x10000000
CFLAGS += $(EXTRA_CFLAGS)

SRC = $(wildcard *.c)
HEADERS = $(wildcard *.h)

OBJS_X64 = $(patsubst %.c, %.x64.o, $(SRC))

all: $(OBJS_X64)


%.x64.o: %.c $(HEADERS)
	@echo "[+] Building $@ (CS 4.9+ compatible)"
	$(CC_X64) $(CFLAGS) -c -o $@ $<
	@if command -v $(STRIP_X64) >/dev/null 2>&1; then \
		$(STRIP_X64) --strip-unneeded $@ 2>/dev/null || true; \
	fi

clean:
	rm -f *.o *.x64.o *.x86.o

.PHONY: all clean

