TEST_INC = -I../include -I$(top_srcdir)/include
TEST_LIB = ../src/libgolle.la

AM_COLOR_TESTS=always

#These are the programs that will be tested
check_PROGRAMS = \
	list\
	buffer\
	randomness\
	commitment\
	keygen\
	distribution\
	elgamal \
	pep \
	schnorr \
	disj \
	dispep 


#Make list test
list_SOURCES = list.c
list_LDADD = $(TEST_LIB)
list_CPPFLAGS = $(TEST_INC)

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

#Make schnorr identification test
schnorr_SOURCES = schnorr.c
schnorr_CPPFLAGS = $(TEST_INC)
schnorr_LDADD = $(TEST_LIB)

#Make the PEP test
pep_SOURCES = pep.c
pep_CPPFLAGS = $(TEST_INC)
pep_LDADD = $(TEST_LIB)

#Make the test for disjunctive schnorr
disj_SOURCES = disj.c
disj_CPPFLAGS = $(TEST_INC)
disj_LDADD = $(TEST_LIB)

#Make the test for DISPEP
dispep_SOURCES = dispep.c
dispep_CPPFLAGS = $(TEST_INC)
dispep_LDADD = $(TEST_LIB)


# Run all test programs
TESTS = ./elgamal\
	./keygen\
	./distribution\
	./commitment\
	./randomness\
	./buffer\
	./pep \
	./schnorr \
	./disj \
	./dispep  \
	./list
