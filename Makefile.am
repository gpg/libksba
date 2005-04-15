# Makefile.am - main makefile for libksba
#     	Copyright (C) 2001, 2002 g10 Code GmbH
# 
# This file is part of KSBA.
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

## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = dist-bzip2

EXTRA_DIST = README-alpha autogen.sh


if CROSS_COMPILING
tests =
else
tests = tests
endif


SUBDIRS = src ${tests} doc

dist-hook:
	@set -e; echo "$(VERSION)" > $(distdir)/VERSION



