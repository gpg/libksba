dnl Macros to configure Libksba
dnl Copyright (C) 2003 g10 Code GmbH
dnl               2003 Free Software Foundation, Inc.
dnl
dnl This file is part of Libksba.
dnl
dnl Libksba is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as
dnl published by the Free Software Foundation; either version 2.1 of
dnl the License, or (at your option) any later version.
dnl
dnl Libksba is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public
dnl License along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA



dnl AM_PATH_GPG_ERROR([MINIMUM-VERSION,
dnl                   [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libgpg-error and define GPG_ERROR_CFLAGS and GPG_ERROR_LIBS
dnl
AC_DEFUN(AM_PATH_GPG_ERROR,
[ AC_ARG_WITH(gpg-error-prefix,
            AC_HELP_STRING([--with-gpg-error-prefix=PFX],
                           [prefix where GPG Error is installed (optional)]),
     gpg_error_config_prefix="$withval", gpg_error_config_prefix="")
  if test x$gpg_error_config_prefix != x ; then
     if test x${GPG_ERROR_CONFIG+set} != xset ; then
        GPG_ERROR_CONFIG=$gpg_error_config_prefix/bin/gpg-error-config
     fi
  fi

  AC_PATH_PROG(GPG_ERROR_CONFIG, gpg-error-config, no)
  min_gpg_error_version=ifelse([$1], ,0.0,$1)
  AC_MSG_CHECKING(for GPG Error - version >= $min_gpg_error_version)
  ok=no
  if test "$GPG_ERROR_CONFIG" != "no" ; then
    req_major=`echo $min_gpg_error_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_gpg_error_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    gpg_error_config_version=`$GPG_ERROR_CONFIG $gpg_error_config_args --version`
    major=`echo $gpg_error_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
    minor=`echo $gpg_error_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
    if test "$major" -gt "$req_major"; then
        ok=yes
    else 
        if test "$major" -eq "$req_major"; then
            if test "$minor" -ge "$req_minor"; then
               ok=yes
            fi
        fi
    fi
  fi
  if test $ok = yes; then
    GPG_ERROR_CFLAGS=`$GPG_ERROR_CONFIG $gpg_error_config_args --cflags`
    GPG_ERROR_LIBS=`$GPG_ERROR_CONFIG $gpg_error_config_args --libs`
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
  else
    GPG_ERROR_CFLAGS=""
    GPG_ERROR_LIBS=""
    AC_MSG_RESULT(no)
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(GPG_ERROR_CFLAGS)
  AC_SUBST(GPG_ERROR_LIBS)
])

