# configure.ac - for libksba
#       Copyright (C) 2001, 2002, 2003, 2004, 2005 g10 Code GmbH
# 
# This file is part of KSBA
# 
# KSBA is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# KSBA is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.57)
min_automake_version="1.9.3"

# Version number: Remember to change immediately *after* a release.
#                 Append a "-cvs" for non-released versions.
AC_INIT(libksba, 0.9.13-cvs, gpa-dev@gnupg.org)
# LT Version numbers: Remember to change them just *before* a release.
#   (Interfaces removed:    CURRENT++, AGE=0, REVISION=0)
#   (Interfaces added:      CURRENT++, AGE++, REVISION=0)
#   (No interfaces changed:                   REVISION++)
# Please remember to document interface changes in the NEWS file.
LIBKSBA_LT_CURRENT=14
LIBKSBA_LT_AGE=6
LIBKSBA_LT_REVISION=1
#-------------------

# fixme: When bouncing this to a newer version, you check whether the
# declaration tests for some symbols can be removed.
NEED_GPG_ERROR_VERSION=0.7


PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_SRCDIR([src/ksba.h])
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)
AM_CONFIG_HEADER(config.h)

AC_GNU_SOURCE


AM_MAINTAINER_MODE


AC_SUBST(LIBKSBA_LT_CURRENT)
AC_SUBST(LIBKSBA_LT_AGE)
AC_SUBST(LIBKSBA_LT_REVISION)
AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])



# Checks for programs.
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
gl_EARLY
#AC_ARG_PROGRAM
AC_PROG_YACC
AC_C_INLINE

AM_PROG_LIBTOOL

if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
fi


# For some systems we know that we have ld_version scripts.  
# Use it then as default.
have_ld_version_script=no
case "${host}" in
    *-*-linux*)
	have_ld_version_script=yes
        ;;
    *-*-gnu*)
	have_ld_version_script=yes
        ;;
esac
AC_ARG_ENABLE([ld-version-script],
              AC_HELP_STRING([--enable-ld-version-script],
                             [enable/disable use of linker version script.
                              (default is system dependent)]),
              [have_ld_version_script=$enableval],
              [ : ] )
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")


# Checks for libraries.

AM_PATH_GPG_ERROR("$NEED_GPG_ERROR_VERSION")
if test "x$GPG_ERROR_LIBS" = "x"; then
  AC_MSG_ERROR([libgpg-error is needed.
                See ftp://ftp.gnupg.org/gcrypt/libgpg-error/ .])
fi
_tmp_gpg_error_save_cflags="$CFLAGS"
CFLAGS="$CFLAGS $GPG_ERROR_CFLAGS"
AC_CHECK_DECLS(GPG_ERR_UNKNOWN_CRIT_EXTN,,,[#include <gpg-error.h>])
CFLAGS="${_tmp_gpg_error_save_cflags}"

AC_DEFINE(GPG_ERR_SOURCE_DEFAULT, GPG_ERR_SOURCE_KSBA,
          [The default error source for libksba.])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

AC_C_BIGENDIAN

AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long)
GNUPG_CHECK_TYPEDEF(u32, HAVE_U32_TYPEDEF)


# Checks for library functions.
AC_CHECK_FUNCS([memmove strchr strtol strtoul stpcpy gmtime_r])


# GNUlib checks
gl_SOURCE_BASE(gl)
gl_M4_BASE(gl/m4)
gl_MODULES(alloca)
gl_INIT

# To be used in ksba-config
KSBA_CONFIG_LIBS="-lksba"
KSBA_CONFIG_CFLAGS=""
AC_SUBST(KSBA_CONFIG_LIBS)
AC_SUBST(KSBA_CONFIG_CFLAGS)

# The Makefiles need to know about cross compiling
AM_CONDITIONAL(CROSS_COMPILING, test x$cross_compiling = xyes)

AC_CONFIG_FILES([
Makefile
gl/Makefile
src/Makefile
src/ksba-config
tests/Makefile
doc/Makefile
])
AC_OUTPUT


echo "
        Libksba v${VERSION} has been configured as follows:
        
        Platform:  $host

"
if test x$cross_compiling = xyes; then
echo "Hint: If you encounter make problems like
  \"No rule to make target 'asn1-tables.c'\"
you should first do a native build without installing
the software, then a \"make distclean\" and then
run the cross compilation again.
"
fi
