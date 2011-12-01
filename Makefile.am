# Makefile.am - main makefile for libksba
#     	Copyright (C) 2001, 2002 g10 Code GmbH
#
# This file is part of KSBA.
#
# KSBA is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# KSBA is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4 -I gl/m4
AUTOMAKE_OPTIONS = dist-bzip2

EXTRA_DIST = autogen.sh 						\
             ChangeLog-2011 doc/ChangeLog-2011 src/ChangeLog-2011 	\
             tests/ChangeLog-2011 			     		\
             build-aux/gitlog-to-changelog build-aux/git-log-footer	\
             build-aux/git-log-fix


if CROSS_COMPILING
tests =
else
tests = tests
endif


SUBDIRS = m4 gl src ${tests} doc

dist-hook: gen-ChangeLog
	@set -e; echo "$(VERSION)" > $(distdir)/VERSION


gen_start_date = 2011-12-01T00:00:00
.PHONY: gen-ChangeLog
gen-ChangeLog:
	if test -d $(top_srcdir)/.git; then				\
	  (cd $(top_srcdir) &&                      			\
	    ./build-aux/gitlog-to-changelog				\
	    --amend=build-aux/git-log-fix				\
	    --since=$(gen_start_date) ) > $(distdir)/cl-t;		\
          cat $(top_srcdir)/build-aux/git-log-footer >> $(distdir)/cl-t;\
	  rm -f $(distdir)/ChangeLog;					\
	  mv $(distdir)/cl-t $(distdir)/ChangeLog;			\
	fi



stowinstall:
	$(MAKE) $(AM_MAKEFLAGS) install prefix=/usr/local/stow/libksba
