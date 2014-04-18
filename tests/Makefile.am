TEST_INC =  -I$(top_srcdir)/include
TEST_LIB =$(top_srcdir)/src/libgolle.la


check_PROGRAMS = \
	list\
	set\
	buffer\
	randomness\
	commitment\
	keygen\
	distribution\
	elgamal

#Make list test
list_SOURCES = $(srcdir)/list.c
list_LDADD = $(TEST_LIB)
list_CPPFLAGS = $(TEST_INC)

#Make set test
set_SOURCES = $(srcdir)/set.c
set_LDADD = $(TEST_LIB)
set_CPPFLAGS = $(TEST_INC) -DDEBUG

#Make buffer test
buffer_SOURCES = $(srcdir)/buffer.c
buffer_LDADD = $(TEST_LIB)
buffer_CPPFLAGS = $(TEST_INC)

#Make random test
randomness_SOURCES = $(srcdir)/randomness.c
randomness_CPPFLAGS = $(TEST_INC)
randomness_LDADD = $(TEST_LIB)

#Make bit commitment test
commitment_SOURCES = $(srcdir)/commitment.c
commitment_CPPFLAGS = $(TEST_INC)
commitment_LDADD = $(TEST_LIB)

#Make Pedersen distribution test
distribution_SOURCES = $(srcdir)/distribution.c
distribution_CPPFLAGS = $(TEST_INC)
distribution_LDADD = $(TEST_LIB)

#Make key generation test
keygen_SOURCES = $(srcdir)/keygen.c
keygen_CPPFLAGS = $(TEST_INC)
keygen_LDADD = $(TEST_LIB)

#Make ElGamal crytposystem test
elgamal_SOURCES = $(srcdir)/elgamal.c
elgamal_CPPFLAGS = $(TEST_INC)
elgamal_LDADD = $(TEST_LIB)

TESTS = list\
	set\
	buffer\
	randomness\
	commitment\
	keygen\
	distribution\
	elgamal
