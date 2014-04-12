TEST_INC =  -I$(top_srcdir)/include
TEST_LIB =$(top_srcdir)/src/libgolle.la


check_PROGRAMS = list set buffer randomness commitment distribution

list_SOURCES = $(srcdir)/list.c
list_LDADD = $(TEST_LIB)
list_CPPFLAGS = $(TEST_INC)


set_SOURCES = $(srcdir)/set.c
set_LDADD = $(TEST_LIB)
set_CPPFLAGS = $(TEST_INC) -DDEBUG

buffer_SOURCES = $(srcdir)/buffer.c
buffer_LDADD = $(TEST_LIB)
buffer_CPPFLAGS = $(TEST_INC)

randomness_SOURCES = $(srcdir)/randomness.c
randomness_CPPFLAGS = $(TEST_INC)
randomness_LDADD = $(TEST_LIB)


commitment_SOURCES = $(srcdir)/commitment.c
commitment_CPPFLAGS = $(TEST_INC)
commitment_LDADD = $(TEST_LIB)


distribution_SOURCES = $(srcdir)/distribution.c
distribution_CPPFLAGS = $(TEST_INC)
distribution_LDADD = $(TEST_LIB)


TESTS = list set buffer randomness commitment distribution
