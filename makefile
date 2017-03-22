#
# Copyright (c) 2017 Darren Smith
#
# wampcc is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#


CXXFLAGS += -MMD -MP
CXXFLAGS += -Wall -O0 -g3 -ggdb -std=c++11 -pthread

LDLIBS += -lcrypto -lssl

# default: callee

all_srcs := $(shell find . -name \*.c)
app_srcs := $(shell find . -name \*.c)

all   : apps
apps  : $(app_srcs:%.c=%)
test  : obj/test/main ; @$<
clean : ; rm -f $(app_srcs:%.c=%) $(app_srcs:%.c=%.d)

#-include $(all_srcs:%.cc=%.d)
.PRECIOUS : %.o

%.o            : %.cc ; $(COMPILE.cpp) $(OUTPUT_OPTION) $<
%.o            : %.c ; $(COMPILE.c) $(OUTPUT_OPTION) $<
%              : %.o ; @$(LINK.cpp) $(OUTPUT_OPTION) $^  $(LDLIBS)
