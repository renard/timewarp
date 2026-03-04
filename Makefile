CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11
LDFLAGS =

all: timewarp timewarp-ctl

timewarp: timewarp.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

timewarp-ctl: timewarp-ctl.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f timewarp timewarp-ctl

.PHONY: all clean
