# configure.ac - for libksba
# Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 g10 Code GmbH
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA.

# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.61)
min_automake_version="1.10"


# Remember to change the version number immediately *after* a release.
# Set my_issvn to "yes" for non-released code.  Remember to run an
# "svn up" and "autogen.sh" right before creating a distribution.
m4_define([my_version], [1.0.2])
m4_define([my_issvn], [yes])

m4_define([svn_revision], m4_esyscmd([echo -n $( (svn info 2>/dev/null \
          || echo 'Revision: 0')|sed -n '/^Revision:/ s/[^0-9]//gp'|head -1)]))
AC_INIT([libksba], my_version[]m4_if(my_issvn,[yes],[-svn[]svn_revision]),
        [gnupg-devel@gnupg.org])

# LT Version numbers: Remember to change them just *before* a release.
#   (Interfaces removed:    CURRENT++, AGE=0, REVISION=0)
#   (Interfaces added:      CURRENT++, AGE++, REVISION=0)
#   (No interfaces changed:                   REVISION++)
# Please remember to document interface changes in the NEWS file.
LIBKSBA_LT_CURRENT=17
LIBKSBA_LT_AGE=9
LIBKSBA_LT_REVISION=1
#-------------------
# If the API is changed in an incompatible way: increment the next counter.
KSBA_CONFIG_API_VERSION=1


NEED_GPG_ERROR_VERSION=1.4

BUILD_REVISION=svn_revision
PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_SRCDIR([src/ksba.h])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)
AM_CONFIG_HEADER(config.h)
AB_INIT

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
AM_PROG_CC_C_O
if test "x$ac_cv_prog_cc_c89" = "xno" ; then
  AC_MSG_ERROR([[No C-89 compiler found]])
fi
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
gl_EARLY
#AC_ARG_PROGRAM
AC_PROG_YACC
AC_C_INLINE

AC_LIBTOOL_WIN32_DLL
AC_LIBTOOL_RC
AM_PROG_LIBTOOL

if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"

    AC_MSG_CHECKING([if gcc supports -Wpointer-arith])
    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wpointer-arith"
    AC_COMPILE_IFELSE(AC_LANG_PROGRAM([]),_gcc_wopt=yes,_gcc_wopt=no)
    AC_MSG_RESULT($_gcc_wopt)
    CFLAGS=$_gcc_cflags_save;
    if test x"$_gcc_wopt" = xyes ; then
       CFLAGS="$CFLAGS -Wpointer-arith"
    fi

    AC_MSG_CHECKING([if gcc supports -Wno-pointer-sign])
    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wno-pointer-sign"
    AC_COMPILE_IFELSE(AC_LANG_PROGRAM([]),_gcc_psign=yes,_gcc_psign=no)
    AC_MSG_RESULT($_gcc_psign)
    CFLAGS=$_gcc_cflags_save;
    if test x"$_gcc_psign" = xyes ; then
       CFLAGS="$CFLAGS -Wno-pointer-sign"
    fi

fi

# Setup some stuff depending on host/target.
have_w32_system=no
case "${target}" in
    *-*-mingw32*)
      have_w32_system=yes
      ;;
    *)
      ;;
esac
if test "$have_w32_system" = yes; then
   AC_DEFINE(HAVE_W32_SYSTEM,1, [Defined if we run on a W32 API based system])
fi
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)


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
AC_SUBST(KSBA_CONFIG_API_VERSION)

# The Makefiles need to know about cross compiling
AM_CONDITIONAL(CROSS_COMPILING, test x$cross_compiling = xyes)


# Generate extended version information for W32.
if test "$have_w32_system" = yes; then
   BUILD_TIMESTAMP=`date --iso-8601=minutes`
   changequote(,)dnl 
   BUILD_FILEVERSION=`echo "$VERSION" | sed 's/\([0-9.]*\).*/\1./;s/\./,/g'`
   changequote([,])dnl
   BUILD_FILEVERSION="${BUILD_FILEVERSION}${BUILD_REVISION}"
fi
AC_SUBST(BUILD_REVISION)
AC_SUBST(BUILD_TIMESTAMP)
AC_SUBST(BUILD_FILEVERSION)
AC_DEFINE_UNQUOTED(BUILD_REVISION, "$BUILD_REVISION", 
                   [Subversion revision used to build this package])


AC_CONFIG_FILES([
Makefile
gl/Makefile
src/Makefile
src/ksba-config
src/versioninfo.rc
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
