override CC_X64 := x86_64-w64-mingw32-gcc
CC_X86 ?= i686-w64-mingw32-gcc
STRIP_X64 ?= x86_64-w64-mingw32-strip
STRIP_X86 ?= i686-w64-mingw32-strip

# Check compiler availability
COMPILER_X64_AVAILABLE := $(shell command -v $(CC_X64) >/dev/null 2>&1 && echo yes || echo no)
COMPILER_X86_AVAILABLE := $(shell command -v $(CC_X86) >/dev/null 2>&1 && echo yes || echo no)

# Standard BOF compilation flags
CFLAGS := -c -Os -std=c99 \
  -fno-stack-protector -fno-stack-check -mno-stack-arg-probe \
  -fno-builtin -fno-builtin-memset -fno-builtin-memcpy -fno-builtin-memmove \
  -ffunction-sections -fdata-sections -nostdlib \
  -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident \
  -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable \
  -fno-leading-underscore -fno-ms-extensions

SRC = $(wildcard *.c)
HEADERS = $(wildcard *.h)
OBJS_X64 = $(patsubst %.c, %.x64.o, $(SRC))
OBJS_X86 = $(if $(filter yes,$(COMPILER_X86_AVAILABLE)),$(patsubst %.c, %.x86.o, $(SRC)),)

all: $(OBJS_X64) $(OBJS_X86)

# Object files depend on source AND all headers
%.x64.o: %.c $(HEADERS)
	@echo "Building x64: $@"
	$(CC_X64) $(CFLAGS) -o $@ $<
	@if command -v $(STRIP_X64) > /dev/null 2>&1; then \
		$(STRIP_X64) --strip-unneeded $@ 2>/dev/null || true; \
	fi

%.x86.o: %.c $(HEADERS)
	@if [ "$(COMPILER_X86_AVAILABLE)" != "yes" ]; then \
		echo "WARNING: $(CC_X86) not available, skipping x86 build for $@"; \
		exit 0; \
	fi
	@echo "Building x86: $@"
	$(CC_X86) $(CFLAGS) -o $@ $<
	@if command -v $(STRIP_X86) > /dev/null 2>&1; then \
		$(STRIP_X86) --strip-unneeded $@ 2>/dev/null || true; \
	fi

clean:
	rm -f *.o *.x64.o *.x86.o

