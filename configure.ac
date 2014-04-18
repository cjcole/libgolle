AC_INIT([libgolle],[0.0.0],[anthony.arnold@uqconnect.edu.au])
AC_CONFIG_HEADERS([include/golle/config.h])
AM_INIT_AUTOMAKE([foreign])
AC_CANONICAL_HOST



AC_CONFIG_MACRO_DIR([m4])
LT_INIT([dlopen])

AC_SUBST([LIBTOOL_DEPS])

AC_PROG_LN_S

# Set up C compiler
AC_PROG_CC

AC_HEADER_STDC

AM_PROG_CC_C_O

AC_PROG_CC_STDC

AS_IF([test "x$ac_cv_prog_cc_stdc" == xno],
	    [AC_MSG_ERROR(STD C is required.)], [])


AC_TYPE_UINTMAX_T
AC_TYPE_SIZE_T
AC_C_CONST
AC_C_INLINE
AC_HEADER_ASSERT
AC_FUNC_MALLOC
AX_CFLAGS_WARN_ALL
AX_CFLAGS_STRICT_PROTOTYPES

# Determine bit commitment random sizes
if test "x$COMMIT_RANDOM_BITS" == "x"; then
   COMMIT_RANDOM_BITS=256
fi
AC_MSG_NOTICE([Using $COMMIT_RANDOM_BITS bits for commitment protocol.])

AC_DEFINE_UNQUOTED([COMMIT_RANDOM_BITS], 
		   [$COMMIT_RANDOM_BITS], 
		   [The size of a commitment random block. 
       		    In practice, the size will be rounded up to 
		    the nearest multiple of CHAR_BIT])



# Test for libcrypto
AC_CHECK_LIB([crypto], [RAND_seed], [], [AC_MSG_ERROR(Libcrypto is not found)])
AC_CHECK_LIB([crypto], [EVP_sha512], [], [AC_MSG_ERROR(Libcrypto does not contain EVP_sha512)])

# Test for libssl's cpuid setup call
# If not available, then we can't use hardware random number generator
AC_CHECK_LIB([ssl], [OPENSSL_cpuid_setup])

# Set up documentation
DX_PDF_FEATURE 
DX_PS_FEATURE 
DX_INIT_DOXYGEN(libgolle, Doxyfile, doc)


# Output
AC_CONFIG_FILES([Makefile src/Makefile tools/Makefile tests/Makefile Doxyfile])
AC_OUTPUT
