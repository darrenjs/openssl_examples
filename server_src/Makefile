CC := gcc
INCLUDES += -I../common -I.
CFLAGS   += -Wall -Werror -fdiagnostics-color=always $(INCLUDES)
LDFLAGS  += -L $(INCLUDE) -Wall -Werror -Wextra -fdiagnostics-color=always
LDLIBS   += -lcrypto -lssl

# set vpath
vpath # clear
vpath %.h ../common

ifeq ($(strip $(OPTIM)), yes)
  CFLAGS += -O2
endif

ifneq ($(strip $(DEBUG)), no)
  CFLAGS += -g
endif

SOURCES := $(wildcard *.c wildcard ../common/*.c)
OBJECTS := $(SOURCES:.c=.o)
TARGET  := server

.PHONY: all
all: $(TARGET)      ## compile and copy upstream
	cp $(TARGET) ..

-include autodep

$(TARGET): $(OBJECTS)	## compile target

.PHONY: clean
clean: ## remove garbage
	rm -f $(OBJECTS) $(TARGET) vgcore*
	rm -f ../common/*.o

.PHONY: depend
depend: $(SOURCES) ## do the dependencies
	$(CC) $(INCLUDES) -MM $(SOURCES) > autodep

.PHONY: certs
certs: ## create certificates
	make -C .. certs

.PHONY: help
help:	## display options
	@grep -E '^[a-zA-Z_-]+:.*## .*' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
