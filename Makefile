CC=gcc
CFLAGS ?= -O2
PROGS = sinit
 
all: $(PROGS)
OBJS = builtins.o init.o parser.o util.o devices.o strlcpy.o
ifeq ($(strip $(INIT_BOOTCHART)),true)
	OBJS += bootchart.o
	CFLAGS += -DBOOTCHART=1
endif
#LIBS = -lrt
sinit: $(OBJS) Makefile
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)
	 
clean:
	rm -f *~ $(PROGS) $(OBJS) 
