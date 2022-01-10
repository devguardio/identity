objects := $(patsubst %.c,%.o,$(wildcard *.c))

ik: $(objects)
	 gcc -Wall -o $@ $(objects) -lcrypto

clean:
	rm ik
	rm $(objects)

