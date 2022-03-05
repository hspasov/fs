ifndef CC
	CC=gcc
endif
CFLAGS=-std=c99 -Werror -Wall -Wpedantic -Wextra
SRCS=fs.c
OBJS=$(subst .c,.o,$(SRCS))
RM=rm -f

all: fs

clean:
	$(RM) $(OBJS) fs

