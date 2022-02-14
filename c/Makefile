CC=clang
CFLAGS = -Wall
SOURCES = main.c

include Makefile.in
CFLAGS+=$(IK_CFLAGS)
SOURCES+=$(IK_SOURCES)
OBJECTS := $(addprefix build/,$(patsubst %.c,%.o,$(SOURCES)))

build/%.o:%.c
	@mkdir -p $(@D)
	gcc -c $^ $(CFLAGS) -o $@

ik: $(OBJECTS)
	 gcc $^ -o $@ -lcrypto -lssl

clean:
	rm -rf build

