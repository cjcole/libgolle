GOLLE_INC = -I$(top_srcdir)/include

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status libtool

lib_LTLIBRARIES = libgolle.la
libgolle_la_CPPFLAGS = $(GOLLE_INC)

libgolle_la_LDFLAGS = -no-undefined -version-info 0:0:0

libgolle_la_SOURCES =\
	$(srcdir)/list.c \
	$(srcdir)/set.c \
	$(srcdir)/random.c \
	$(srcdir)/bin.c \
	$(srcdir)/commit.c \
	$(srcdir)/numbers.c \
	$(srcdir)/distribute.c \
	$(srcdir)/elgamal.c \
	$(srcdir)/peer.c
