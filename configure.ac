AC_INIT([LibGolle],[0.0.0],[anthony.arnold@uqconnect.edu.au],[libgolle],[http://anthony-arnold.github.io/libgolle])
AC_CONFIG_HEADERS([include/golle/config.h])
AM_INIT_AUTOMAKE([foreign])
AC_CANONICAL_HOST

AC_CONFIG_MACRO_DIR([m4])
LT_INIT([dlopen])

AC_SUBST([LIBTOOL_DEPS])

AC_PROG_LN_S
dnl Set up the C compiler
AC_PROG_CC

AC_HEADER_STDC
AM_PROG_CC_C_O
AC_PROG_CC_C99
dnl A C99 compiler is required
AS_IF([test "x$ac_cv_prog_cc_c99" == xno],
	    [AC_MSG_ERROR(STD C is required.)], [])
AC_TYPE_UINTMAX_T
AC_TYPE_SIZE_T
AC_C_CONST
AC_C_INLINE
AC_HEADER_ASSERT
AC_FUNC_MALLOC

dnl Fails on some installations
dnl AX_CFLAGS_WARN_ALL

dnl Determine bit commitment random sizes
if test "x$COMMIT_RANDOM_BITS" == "x"; then
   COMMIT_RANDOM_BITS=256
fi
AC_MSG_NOTICE([Using $COMMIT_RANDOM_BITS bits for commitment protocol.])

AC_DEFINE_UNQUOTED([COMMIT_RANDOM_BITS], 
		   [$COMMIT_RANDOM_BITS], 
		   [The size of a commitment random block. 
       		    In practice, the size will be rounded up to 
		    the nearest multiple of CHAR_BIT])

dnl Test for libcrypto
AC_CHECK_LIB([crypto], [EVP_sha512], [], [AC_MSG_ERROR(Libcrypto does not contain EVP_sha512)])

dnl Test for libssl's cpuid setup call
dnl If not available, then we can't use hardware random number generator
AC_CHECK_LIB([ssl], [OPENSSL_cpuid_setup])

dnl Set up documentation
DX_PDF_FEATURE 
DX_PS_FEATURE 
DX_INIT_DOXYGEN(libgolle, Doxyfile, doc)

dnl Output
AC_CONFIG_FILES([Makefile 
			  src/Makefile 
			  tools/Makefile 
			  tests/Makefile 
			  samples/Makefile 
			  Doxyfile])

AC_OUTPUT
