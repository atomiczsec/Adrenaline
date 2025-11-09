# Makefile for user_idle BOF
# Builds x64 and x86 COFF objects for Cobalt Strike
# Reports user idle time + GUI resource pressure (GDI/USER handles)

CC_X64  ?= x86_64-w64-mingw32-gcc
CC_X86  ?= i686-w64-mingw32-gcc

# Optimized flags for BOF compilation (no CRT, minimal size)
CFLAGS_COMMON := -c -Os \
  -fno-stack-protector -fno-stack-check -mno-stack-arg-probe \
  -fno-builtin -ffunction-sections -fdata-sections -nostdlib \
  -fno-asynchronous-unwind-tables -fno-ident \
  -Wall -Wextra -Wno-unused-parameter

TARGET := user_idle
SOURCE := $(TARGET).c
HEADERS := beacon.h

all: $(TARGET).x64.o $(TARGET).x86.o

$(TARGET).x64.o: $(SOURCE) $(HEADERS)
	$(CC_X64) $(CFLAGS_COMMON) -o $@ $<
	@echo "Built x64 BOF: $@"

$(TARGET).x86.o: $(SOURCE) $(HEADERS)
	$(CC_X86) $(CFLAGS_COMMON) -o $@ $<
	@echo "Built x86 BOF: $@"

# Debug target - shows all symbols and relocations
debug: $(TARGET).x64.o
	@echo "=== All symbols in $(TARGET).x64.o ==="
	@objdump -t $(TARGET).x64.o
	@echo "=== Relocations ==="
	@objdump -r $(TARGET).x64.o

clean:
	rm -f *.o

info:
	@echo "user_idle BOF Build System"
	@echo "Targets:"
	@echo "  all     - Build both x64 and x86 BOF objects"
	@echo "  debug   - Build x64 and show all symbols/relocations"
	@echo "  clean   - Remove compiled objects"
	@echo "  info    - Show this help"
	@echo ""
	@echo "Requirements:"
	@echo "  - MinGW-w64 cross-compiler (x86_64-w64-mingw32-gcc, i686-w64-mingw32-gcc)"
	@echo "  - objdump (for symbol inspection)"
	@echo "  - Output: COFF objects for Cobalt Strike BOF loading"

.PHONY: all debug clean info
