TEST_INC =  -I$(top_srcdir)/include
TEST_LIB =../src/libgolle.la


check_PROGRAMS = list set

list_SOURCES = list.c
list_LDADD = $(TEST_LIB)
list_CPPFLAGS = $(TEST_INC)


set_SOURCES = set.c
set_LDADD = $(TEST_LIB)
set_CPPFLAGS = $(TEST_INC) -DDEBUG

TESTS = list set
