#!/usr/bin/make -f

CC = gcc
PROGRAM = main ldap
LDLIBS = -levent -lssl -lldap -llber -levent_openssl
CPPFLAGS += -I $(LIBEVENT_PATH)/include
CFLAGS = -g -Wall

ifdef LIBEVENT_PATH
# libevent 2.1 is still in alpha, so let's set up rpath even though we should not
	LDFLAGS += -L $(LIBEVENT_PATH)/lib -Wl,--enable-new-dtags,--rpath=$(LIBEVENT_PATH)/lib
endif

.PHONY: clean all

all: $(PROGRAM)

$(PROGRAM):

ldap: lber.c io_handler.h

main: imap.c ssl.c avl/avl.o

clean:
	rm -rf $(PROGRAM) $(wildcard *.o */*.o) core
