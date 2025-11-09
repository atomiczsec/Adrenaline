CC_x64=x86_64-w64-mingw32-gcc
CC_x86=i686-w64-mingw32-gcc
CFLAGS=-c -fno-builtin -fno-builtin-memset -fno-builtin-memcpy -fno-builtin-memmove -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-stack-protector -fno-stack-check -mno-stack-arg-probe -Os

TARGET := applications_enum

all: $(TARGET).x86.o $(TARGET).x64.o

$(TARGET).x86.o: $(TARGET).c
	$(CC_x86) $(CFLAGS) -o $@ $<

$(TARGET).x64.o: $(TARGET).c
	$(CC_x64) $(CFLAGS) -o $@ $<

clean:
	rm -f *.o
