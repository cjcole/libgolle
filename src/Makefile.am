GOLLE_INC = -I../include -I$(top_srcdir)/include

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status libtool

lib_LTLIBRARIES = libgolle.la
libgolle_la_CPPFLAGS = $(GOLLE_INC)

libgolle_la_LDFLAGS = -no-undefined -version-info 0:0:0

libgolle_la_SOURCES =\
	list.c \
	set.c \
	random.c \
	bin.c \
	commit.c \
	numbers.c \
	distribute.c \
	elgamal.c \
	peer.c \
	select.c
