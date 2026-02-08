override CC_X64 := x86_64-w64-mingw32-gcc
STRIP_X64 ?= x86_64-w64-mingw32-strip


COMPILER_X64_AVAILABLE := yes
COMPILER_X86_AVAILABLE := no


CFLAGS := -Os -std=c99 \
	-fno-stack-protector -fno-stack-check -mno-stack-arg-probe \
	-fno-builtin -fno-builtin-memset -fno-builtin-memcpy -fno-builtin-memmove \
	-ffunction-sections -fdata-sections -nostdlib \
	-fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident \
	-Wall -Wextra -Wno-unused-parameter -Wno-unused-variable \
	-fno-leading-underscore -fno-ms-extensions


SRC = $(wildcard *.c)
HEADERS = $(wildcard *.h)

OBJS_X64 = $(patsubst %.c, %.x64.o, $(SRC))

all: $(OBJS_X64)


%.x64.o: %.c $(HEADERS)
	@echo "Building x64: $@"
	$(CC_X64) $(CFLAGS) -c -o $@ $<
	@if command -v $(STRIP_X64) >/dev/null 2>&1; then \
		$(STRIP_X64) --strip-unneeded $@ 2>/dev/null || true; \
	fi


clean:
	rm -f *.o *.x64.o *.x86.o
