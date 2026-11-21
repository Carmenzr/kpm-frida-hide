KP_DIR ?= KernelPatch
CC = aarch64-linux-gnu-gcc
STRIP = aarch64-linux-gnu-strip

INCLUDE_DIRS := include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := -I. $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS = $(INCLUDE_FLAGS) -Wall -O2 -ffreestanding -fno-PIC \
	-fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables \
	-fno-semantic-interposition -U_FORTIFY_SOURCE -fno-common -fvisibility=hidden

objs := kpm_frida_hide.o

all: kpm-frida-hide.kpm

kpm-frida-hide.kpm: $(objs)
	$(CC) -r -nostdlib -o $@ $^
	$(STRIP) -g --strip-unneeded --strip-debug --remove-section=.comment --remove-section=.note.GNU-stack $@

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.kpm