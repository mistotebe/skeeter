#!/usr/bin/make -f

.PHONY: clean all

all:

PROGRAM = main
OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
DEPS = $(OBJS:%.o=%.d)
CLEAN = $(PROGRAM) $(OBJS) $(DEPS)

LDLIBS = -levent -lssl -lldap -llber -levent_openssl -lcrypto -lconfig
CFLAGS = -g -Wall

ifdef LIBEVENT_PATH
# libevent 2.1 is still in alpha, so let's set up rpath even though we should not
	LDFLAGS += -L $(LIBEVENT_PATH)/lib -Wl,--enable-new-dtags,--rpath=$(LIBEVENT_PATH)/lib
	CPPFLAGS += -I $(LIBEVENT_PATH)/include
endif

%.d: %.c
	$(CC) -MM -MF $@ -MT $@ -MT $*.o $<

d :=
sp :=
dir := avl
include $(dir)/Rules.mk
dir := test
include $(dir)/Rules.mk

all: $(PROGRAM)

$(PROGRAM):

main: $(OBJS)

clean:
	rm -rf $(CLEAN) core

# so that cleaning does not trigger remaking the dependency information
#
# note that there might be other targets that do not need this information, but
# this only considers the "clean" target
ifneq ($(findstring clean,$(MAKECMDGOALS)),clean)
-include $(DEPS)
endif
