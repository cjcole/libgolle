GOLLE_INC = -I$(top_srcdir)/include

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status libtool

lib_LTLIBRARIES = libgolle.la
libgolle_la_CPPFLAGS = $(GOLLE_INC)
libgolle_la_SOURCES = $(srcdir)/list.c $(srcdir)/set.c $(srcdir)/num.c
libgolle_la_LDFLAGS = -no-undefined -version-info 0:0:0 $(LIBM)


$(srcdir)/num.c: $(NUM_IMPL)
	test -z "$(srcdir)/num.c" | rm -f $(srcdir)/num.c
	$(LN_S) $(srcdir)/$(NUM_IMPL) $(srcdir)/num.c


CLEANFILES=$(srcdir)/num.c