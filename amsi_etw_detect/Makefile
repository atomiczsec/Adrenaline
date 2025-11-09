# Makefile for AMSI/ETW Detect BOF

CC_X64  ?= x86_64-w64-mingw32-gcc
CC_X86  ?= i686-w64-mingw32-gcc

CFLAGS_COMMON := -c -Os -std=c99 \
  -fno-stack-protector -fno-stack-check -mno-stack-arg-probe \
  -fno-builtin -fno-builtin-memset -fno-builtin-memcpy -fno-builtin-memmove \
  -ffunction-sections -fdata-sections -nostdlib \
  -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident \
  -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable

CFLAGS_COMMON += -fno-leading-underscore -fno-ms-extensions

TARGET := amsi_etw_detect
SOURCE := $(TARGET).c
HEADERS := beacon.h

all: $(TARGET).x64.o $(TARGET).x86.o

$(TARGET).x64.o: $(SOURCE) $(HEADERS)
	$(CC_X64) $(CFLAGS_COMMON) -o $@ $<
	@echo "Built x64 BOF: $@"
	@echo "Checking symbols in $@..."
	@objdump -t $@ | grep -E "(GetModuleHandleW|GetProcAddress|KERNEL32$GetModuleHandleW|KERNEL32$GetProcAddress)" || echo "No problematic symbols found"

$(TARGET).x86.o: $(SOURCE) $(HEADERS)
	$(CC_X86) $(CFLAGS_COMMON) -o $@ $<
	@echo "Built x86 BOF: $@"
	@echo "Checking symbols in $@..."
	@objdump -t $@ | grep -E "(GetModuleHandleW|GetProcAddress|KERNEL32$GetModuleHandleW|KERNEL32$GetProcAddress)" || echo "No problematic symbols found"


debug: $(TARGET).x64.o
	@echo "=== All symbols in $(TARGET).x64.o ==="
	@objdump -t $(TARGET).x64.o
	@echo "=== Relocations ==="
	@objdump -r $(TARGET).x64.o


verbose: $(SOURCE) $(HEADERS)
	$(CC_X64) $(CFLAGS_COMMON) -v -o $(TARGET).x64.o $<

clean:
	rm -f *.o

info:
	@echo "AMSI/ETW Detect BOF Build System"
	@echo "Targets:"
	@echo "  all     - Build both x64 and x86 BOF objects"
	@echo "  debug   - Build x64 and show all symbols/relocations"
	@echo "  verbose - Build with verbose compiler output"
	@echo "  clean   - Remove compiled objects"
	@echo "  info    - Show this help"
	@echo ""
	@echo "Requirements:"
	@echo "  - MinGW-w64 cross-compiler (x86_64-w64-mingw32-gcc, i686-w64-mingw32-gcc)"
	@echo "  - objdump (for symbol inspection)"
	@echo "  - Output: COFF objects for Cobalt Strike BOF loading and COFFLoader"

.PHONY: all debug verbose clean info