sp := $(sp).x
dirstack_$(sp) := $(d)
d := $(dir)

PROGRAM_check := $(d)/run_tests

OBJS_check := $(patsubst %.c,%.o,$(wildcard $(d)/*.c))
DEPS += $(OBJS_check:%.o=%.d)
CLEAN += $(PROGRAM_check) $(OBJS_check)

.PHONY: check

check: $(PROGRAM_check)
	$(PROGRAM_check)

$(PROGRAM_check):

$(PROGRAM_check): LDLIBS += $(shell pkg-config --libs check)
$(PROGRAM_check): $(OBJS_check) avl/avl.o

d := $(dirstack_$(sp))
sp := $(basename $(sp))
