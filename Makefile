CPPFLAGS=-isysroot $(IOS_SDK) -arch arm64 -mios-version-min=12.0 -DDEBUG=1
ASFLAGS=-arch arm64
LDFLAGS=-lc++ -framework CoreFoundation -framework IOKit

SRC=\
SockPuppet2/dangling_options.c \
SockPuppet2/drop_payload.c \
SockPuppet2/exploit.c \
SockPuppet2/iosurface.c \
SockPuppet2/kernel_alloc.c \
SockPuppet2/kernel_memory.c \
SockPuppet2/log.c \
SockPuppet2/parameters.c \
SockPuppet2/pipe.c \
SockPuppet2/platform.c \
SockPuppet2/platform_match.c \
SockPuppet2/port.c \
SockPuppet2/spray.c \
SockPuppet2/stage1.c \
SockPuppet2/util.c

OBJ=$(SRC:.c=.o)

SockPuppet2/SockPuppet2.dylib: SockPuppet2/main.o $(OBJ) loader/loader.bin payload/amfid_payload.dylib payload/safari_payload.dylib
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -dynamiclib -o $@ SockPuppet2/main.o $(OBJ)

SockPuppet2/SockPuppet2_debug: SockPuppet2/main.c $(OBJ) loader/loader.bin payload/amfid_payload.dylib payload/safari_payload.dylib
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -DMAIN -o $@ SockPuppet2/main.c $(OBJ)
	jtool --sign --inplace --ent SockPuppet2/bin.ent $@

loader/loader.bin: loader/loader.o
	gobjcopy -Obinary $^ $@

payload/safari_payload.dylib: payload/safari_payload.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -framework CoreFoundation -framework UIKit -dynamiclib -o $@ $^
	jtool --sign --inplace $@

clean:
	rm -f SockPuppet2/SockPuppet2.dylib SockPuppet2/SockPuppet2_debug $(OBJ) loader/loader.bin loader/loader.o payload/safari_payload.dylib payload/safari_payload.o

.PHONY: clean
