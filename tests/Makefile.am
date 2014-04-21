TEST_INC = -I../include -I$(top_srcdir)/include
TEST_LIB = ../src/libgolle.la

AM_COLOR_TESTS=always

EXTRA_DIST = runtest

#These are the programs that will be tested
check_PROGRAMS = \
	list\
	set\
	buffer\
	randomness\
	commitment\
	keygen\
	distribution\
	elgamal \
	p2p

#Make list test
list_SOURCES = list.c
list_LDADD = $(TEST_LIB)
list_CPPFLAGS = $(TEST_INC)

#Make set test
set_SOURCES = set.c
set_LDADD = $(TEST_LIB)
set_CPPFLAGS = $(TEST_INC) -DDEBUG

#Make buffer test
buffer_SOURCES = buffer.c
buffer_LDADD = $(TEST_LIB)
buffer_CPPFLAGS = $(TEST_INC)

#Make random test
randomness_SOURCES = randomness.c
randomness_CPPFLAGS = $(TEST_INC)
randomness_LDADD = $(TEST_LIB)

#Make bit commitment test
commitment_SOURCES = commitment.c
commitment_CPPFLAGS = $(TEST_INC)
commitment_LDADD = $(TEST_LIB)

#Make Pedersen distribution test
distribution_SOURCES = distribution.c
distribution_CPPFLAGS = $(TEST_INC)
distribution_LDADD = $(TEST_LIB)

#Make key generation test
keygen_SOURCES = keygen.c
keygen_CPPFLAGS = $(TEST_INC)
keygen_LDADD = $(TEST_LIB)

#Make ElGamal crytposystem test
elgamal_SOURCES = elgamal.c
elgamal_CPPFLAGS = $(TEST_INC)
elgamal_LDADD = $(TEST_LIB)

#Make peer set distribution test
p2p_SOURCES = p2p.c
p2p_CPPFLAGS = $(TEST_INC)
p2p_LDADD = $(TEST_LIB)


TESTS = ./list\
	./elgamal\
	./keygen\
	./distribution\
	./commitment\
	./randomness\
	./buffer\
	./p2p\
	./set
