CC_x64=x86_64-w64-mingw32-gcc
CC_x86=i686-w64-mingw32-gcc
CFLAGS=-c -fno-builtin -fno-builtin-memset -fno-builtin-memcpy -fno-builtin-memmove -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-stack-protector -fno-stack-check -mno-stack-arg-probe -Os

all: bof_implant.o bof_implant_x64.o

bof_implant.o: bof_implant.c
	$(CC_x86) $(CFLAGS) -o $@ $<

bof_implant_x64.o: bof_implant.c
	$(CC_x64) $(CFLAGS) -o $@ $<

clean:
	rm -f *.o
