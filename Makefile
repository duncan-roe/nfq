.PHONY: clean
SRCS = $(wildcard *.c)
PROG = $(shell basename $$PWD)
LIBS = -lmnl -lnetfilter_queue
OBJ = $(SRCS:.c=.o)
CPPFLAGS = $(shell getconf LFS_CFLAGS 2>/dev/null)
CFLAGS = -g3 -ggdb \
  -Wall -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wstrict-prototypes \
  -Wmissing-prototypes
$(PROG) : $(OBJ)
	$(CC) $^ -o $@ $(LIBS)
clean :
	rm -f *.o *.d $(PROG)

# Auto dependency stuff (from info make)
%.d: %.c
	$(CC) -MM -MT $(@:.d=.o) -MT $@ $(CPPFLAGS) $< -o $@
ifneq ($(MAKECMDGOALS),clean)
-include $(SRCS:.c=.d)
endif
