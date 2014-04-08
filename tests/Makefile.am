TEST_INC =  -I$(top_srcdir)/include
TEST_LIB =$(top_srcdir)/src/libgolle.la $(LIBGMP) $(LIBM)


check_PROGRAMS = list set randomness

list_SOURCES = $(srcdir)/list.c
list_LDADD = $(TEST_LIB)
list_CPPFLAGS = $(TEST_INC)


set_SOURCES = $(srcdir)/set.c
set_LDADD = $(TEST_LIB)
set_CPPFLAGS = $(TEST_INC) -DDEBUG

randomness_SOURCES = $(srcdir)/randomness.c $(top_srcdir)/src/random.c
randomness_CPPFLAGS = $(TEST_INC)

TESTS = list set randomness
