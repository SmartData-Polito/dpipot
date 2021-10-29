CC=gcc
CFLAGS=-fPIC -DPIC -Iinclude -O2 -Wall -Wextra -Wconversion
LIBNDPI=./lib/libndpi.a
LDFLAGS=$(LIBNDPI) -lgcrypt -lpcap -ljson-c -lpthread -lm

OBJECTS = listener.o classifier.o

all 	: $(OBJECTS)
	$(CC) $(CFLAGS) -o classifier lib/libndpi.a $(OBJECTS) $(LDFLAGS)

clean	:
	$(RM) -f  ./*~ ./*.o classifier

