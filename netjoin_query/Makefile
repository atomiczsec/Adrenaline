SRC = $(wildcard *.c)
OBJS = $(patsubst %.c, %.x64.o, $(SRC))
HEADERS = $(wildcard *.h)
CC_x64 := x86_64-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip

# Critical BOF compilation flags
CFLAGS := -c -Os -fno-builtin -fno-builtin-memset -fno-builtin-memcpy -fno-builtin-memmove
CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables
CFLAGS += -fno-stack-protector -fno-stack-check -mno-stack-arg-probe
CFLAGS += -nostdlib -ffunction-sections -fdata-sections

all: $(OBJS)

# Object files depend on source AND all headers
%.x64.o: %.c $(HEADERS)
	$(CC_x64) $(CFLAGS) -o $@ $<
	$(STRIP_x64) --strip-unneeded $@

clean:
	rm -f *.o *.x64.o
