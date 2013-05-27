sp := $(sp).x
dirstack_$(sp) := $(d)
d := $(dir)

OBJS := $(OBJS) $(d)/avl.o

d := $(dirstack_$(sp))
sp := $(basename $(sp))
