#!/bin/sh
# Run this to generate all the initial makefiles, etc.
#
# Copyright (C) 2003 g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

PGM=libksba

# Required version of autoconf.  Keep it in sync with the AC_PREREQ
# macro at the top of configure.ac.
autoconf_vers=2.57

# Required version of automake. 
automake_vers=1.7.6



aclocal_vers="$automake_vers"
ACLOCAL=${ACLOCAL:-aclocal}
AUTOCONF=${AUTOCONF:-autoconf}
AUTOMAKE=${AUTOMAKE:-automake}
AUTOHEADER=${AUTOHEADER:-autoheader}
DIE=no


if ($AUTOCONF --version) < /dev/null > /dev/null 2>&1 ; then
    if ($AUTOCONF --version | awk 'NR==1 { if( $3 >= "'$autoconf_vers'") \
			       exit 1; exit 0; }');
    then
       echo "**Error**: "\`autoconf\'" is too old."
       echo '           (version ' $autoconf_vers ' or newer is required)'
       DIE="yes"
    fi
else
    echo
    echo "**Error**: You must have "\`autoconf\'" installed to compile $PGM."
    echo '           (version ' $autoconf_vers ' or newer is required)'
    DIE="yes"
fi

if ($AUTOMAKE --version) < /dev/null > /dev/null 2>&1 ; then
  if ($AUTOMAKE --version | awk 'NR==1 { if( $4 >= "'$automake_vers'") \
			     exit 1; exit 0; }');
     then
     echo "**Error**: "\`automake\'" is too old."
     echo '           (version ' $automake_vers ' or newer is required)'
     DIE="yes"
  fi
  if ($ACLOCAL --version) < /dev/null > /dev/null 2>&1; then
    if ($ACLOCAL --version | awk 'NR==1 { if( $4 >= "'$aclocal_vers'" ) \
						exit 1; exit 0; }' );
    then
      echo "**Error**: "\`aclocal\'" is too old."
      echo '           (version ' $aclocal_vers ' or newer is required)'
      DIE="yes"
    fi
  else
    echo
    echo "**Error**: Missing "\`aclocal\'".  The version of "\`automake\'
    echo "           installed doesn't appear recent enough."
    DIE="yes"
  fi
else
    echo
    echo "**Error**: You must have "\`automake\'" installed to compile $PGM."
    echo '           (version ' $automake_vers ' or newer is required)'
    DIE="yes"
fi

if test "$DIE" = "yes"; then
    exit 1
fi

echo "Running aclocal ..."
$ACLOCAL
echo "Running autoheader..."
$AUTOHEADER
echo "Running automake --gnu ..."
$AUTOMAKE --gnu;
echo "Running autoconf..."
$AUTOCONF

echo "You may now run \"./configure --enable-maintainer-mode && make\"."
