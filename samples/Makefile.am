GOLLE_INC = -I$(top_srcdir)/include
GOLLE_LIB = ../src/libgolle.la

bin_PROGRAMS = lg-straws lg-elgamal

CPPFLAGS += $(GOLLE_INC)
LDFLAGS += $(GOLLE_LIB)

lg_elgamal_SOURCES = crypto/elgamal.c

lg_straws_SOURCES =\
	straws/args.c\
        straws/globals.c\
	straws/straws.c\
	straws/socklib.c\
	straws/connect_remote.c\
	straws/read_key.c\
	straws/distribution.c\
	straws/draw.c