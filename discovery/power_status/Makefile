SRC = power_status.c
TARGET = power_status

# Toolchain (adjust if using different MinGW installation)
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip
STRIP_x86 := i686-w64-mingw32-strip

# Critical BOF compilation flags
CFLAGS := -c -Os
CFLAGS += -fno-builtin -fno-builtin-memset -fno-builtin-memcpy -fno-builtin-memmove
CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables
CFLAGS += -fno-stack-protector -fno-stack-check -mno-stack-arg-probe
CFLAGS += -ffunction-sections -fdata-sections
CFLAGS += -nostdlib
CFLAGS += -Wall -Wextra -Wno-unused-parameter

.PHONY: all clean x64 x86

# Default: build both architectures
all: x64 x86

# 64-bit target (recommended)
x64: $(TARGET).x64.o

$(TARGET).x64.o: $(SRC) beacon.h
	$(CC_x64) $(CFLAGS) -o $@ $(SRC)
	$(STRIP_x64) --strip-unneeded $@
	@echo "[+] Built: $@ (size: $$(du -h $@ | cut -f1))"

# 32-bit target
x86: $(TARGET).x86.o

$(TARGET).x86.o: $(SRC) beacon.h
	$(CC_x86) $(CFLAGS) -o $@ $(SRC)
	$(STRIP_x86) --strip-unneeded $@
	@echo "[+] Built: $@ (size: $$(du -h $@ | cut -f1))"

# Clean build artifacts
clean:
	rm -f $(TARGET).x64.o $(TARGET).x86.o
	@echo "[+] Cleaned build artifacts"
