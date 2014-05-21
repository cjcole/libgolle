GOLLE_INC = -I$(top_srcdir)/include
GOLLE_LIB = ../../src/libgolle.la $(PTHREAD_LIBS)

bin_PROGRAMS = golle_straws

golle_straws_CFLAGS = $(CFLAGS) $(PTHREAD_CFLAGS)
golle_straws_CPPFLAGS = $(GOLLE_INC)
golle_straws_LDADD = $(GOLLE_LIB)
golle_straws_LDFLAGS = $(PTHREAD_CFLAGS)

golle_straws_SOURCES =\
	args.c\
        globals.c\
	straws.c\
	socklib.c\
	connect_remote.c\
	read_key.c\
	distribution.c
