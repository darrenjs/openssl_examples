#
# Copyright (c) 2017 Darren Smith
#
# ssl_examples is free software; you can redistribute it and/or modify it under
# the terms of the MIT license. See LICENSE for details.
#


CFLAGS += -MMD -MP -Wall -Wextra -O0 -g3 -ggdb

LDLIBS += -lcrypto -lssl

all_srcs := $(shell find . -name \*.c)


all   : apps
apps  : $(all_srcs:%.c=%)
test  : obj/test/main ; @$<
clean : ; rm -f $(all_srcs:%.c=%) $(all_srcs:%.c=%.d)

.PRECIOUS : %.o

ssl_server_nonblock: ssl_server_nonblock.c common.h
	$(CC) $(CFLAGS) ssl_server_nonblock.c $(OUTPUT_OPTION) $(LDLIBS)

ssl_client_nonblock: ssl_client_nonblock.c common.h
	$(CC) $(CFLAGS) ssl_client_nonblock.c $(OUTPUT_OPTION) $(LDLIBS)

#-include $(all_srcs:%.c=%.d)
