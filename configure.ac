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
	    [AC_MSG_ERROR("STD C is required.")], [])


AC_TYPE_UINTMAX_T
AC_TYPE_SIZE_T
AC_C_CONST
AC_C_INLINE
AC_HEADER_ASSERT
AC_FUNC_MALLOC
LT_LIB_M


# Test for libgmp
# Depending on the --with-gmp argument, will warn or error if not available.
AC_ARG_WITH([gmp],
	[AS_HELP_STRING([--with-gmp],[support arbitrarily large numbers @<:@default=check@:>@])],
	[],
	[with_gmp=check])

LIBGMP=
AS_IF([test "x$with_gmp" != xno],
	    [AC_CHECK_LIB([gmp], [__gmpz_init], 
	    			 [AC_SUBST([LIBGMP], ["-lgmp"])
	    			  AC_DEFINE([HAVE_LIBGMP], [1],
				 	   [Defined if you have libgmp])
		                 ],
	    			 [if test "x$with_gmp" != xcheck; then
				   AC_MSG_FAILURE(
				     [--with-gmp was given, but test for GMP failed.])
				  else
					AC_MSG_WARN([GMP was not found. Crypto will not be secure!])
				  fi])
             ],
             [AC_MSG_WARN([--without-gmp was given. Crypto will not be secure!])]
)


# Set up the num_def header file.
echo "LIBGMP=$LIBGMP"
if test x$NUM_DEF = x; then
    if test x$LIBGMP != x; then
      NUM_DEF="num_gmp.h"
    else
      NUM_DEF="num_int.h"
    fi
fi

if test "${NUM_IMPL}+set}" != set; then
    if test x$LIBGMP != x; then
      NUM_IMPL=num_gmp.c
    else
      NUM_IMPL=num_int.c
    fi
fi

echo "Using $NUM_DEF for number definitions."
echo "Using $NUM_IMPL for number implimentation."
AC_SUBST([NUM_DEF], $NUM_DEF)
AC_SUBST([NUM_IMPL], $NUM_IMPL)

# Set up documentation
DX_INIT_DOXYGEN(libgolle, Doxyfile, doc)



# Output
AC_CONFIG_FILES([Doxyfile Makefile src/Makefile tests/Makefile src/num.h])
AC_OUTPUT
