AC_INIT([libgolle],[0.0.0],[anthony.arnold@uqconnect.edu.au])
AM_INIT_AUTOMAKE([foreign])
AC_CANONICAL_HOST



AC_CONFIG_MACRO_DIR([m4])
LT_INIT([dlopen])

AC_SUBST([LIBTOOL_DEPS])



# Set up C compiler
AC_PROG_CC

AC_HEADER_STDC

AM_PROG_CC_C_O

AC_PROG_CC_STDC

AS_IF([test "x$ac_cv_prog_cc_stdc" == xno],
	    [AC_MSG_ERROR("STD C is required.")], [])



AC_TYPE_SIZE_T
AC_C_CONST
AC_C_INLINE
AC_HEADER_ASSERT
AC_FUNC_MALLOC



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


# Set up documentation
DX_INIT_DOXYGEN(libgolle, Doxyfile, doc)



# Output
AC_CONFIG_FILES([Doxyfile Makefile src/Makefile tests/Makefile])
AC_OUTPUT
