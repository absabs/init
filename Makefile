CC=gcc
CFLAGS ?= -pipe -O2 -march=native
PROGS = init shutdown
 
all: $(PROGS)
OBJS = builtins.o init.o parser.o util.o devices.o strlcpy.o
ifeq ($(strip $(INIT_BOOTCHART)),true)
	OBJS += bootchart.o
	CFLAGS += -DBOOTCHART=1
endif
#LIBS = -lrt
init: $(OBJS) Makefile
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)
shutdown: shutdown.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

	 
clean:
	rm -f *~ $(PROGS) $(OBJS) 
