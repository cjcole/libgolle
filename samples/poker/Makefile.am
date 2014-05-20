GOLLE_INC = -I$(top_srcdir)/include
GOLLE_LIB = ../../src/libgolle.la $(PTHREAD_LIBS)

bin_PROGRAMS = golle_poker

golle_poker_CFLAGS = $(CFLAGS) $(PTHREAD_CFLAGS)
golle_poker_CPPFLAGS = $(GOLLE_INC)
golle_poker_LDADD = $(GOLLE_LIB)
golle_poker_LDFLAGS = $(PTHREAD_CFLAGS)

golle_poker_SOURCES =\
	args.c\
        globals.c\
	poker.c\
	socklib.c\
	connect_remote.c\
	read_key.c\
	distribution.c
