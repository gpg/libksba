# Makefile.am - for the KSBA ASN.1 and X.509 library
#       Copyright (C) 2001 g10 Code GmbH
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

EXTRA_DIST = ksba-config.in mkerrors
BUILT_SOURCES = asn1-parse.c errors.c
bin_SCRIPTS = ksba-config
include_HEADERS = ksba.h
lib_LTLIBRARIES = libksba.la
noinst_PROGRAMS = asn1-gentables ber-dump

libksba_la_LDFLAGS = -version-info \
      @LIBKSBA_LT_CURRENT@:@LIBKSBA_LT_REVISION@:@LIBKSBA_LT_AGE@
libksba_la_INCLUDES = -I$(top_srcdir)/lib 

libksba_la_SOURCES = \
	ksba.h \
	ber-decoder.c ber-decoder.h \
	reader.c reader.h \
	asn1-parse.y asn1-parse.h \
	asn1-func.c asn1-func.h \
	cert.c cert.h \
	keyinfo.c keyinfo.h \
	oid.c dn.c time.c convert.h \
	util.c util.h errors.c	

asn1_gentables_SOURCES = \
	asn1-gentables.c \
	asn1-parse.y asn1-parse.h \
	asn1-func.c asn1-func.h \
	oid.c \
	util.c util.h	

ber_dump_SOURCES = \
	ber-dump.c \
	ksba.h \
	ber-decoder.c ber-decoder.h \
	reader.c reader.h \
	asn1-parse.y asn1-parse.h \
	asn1-func.c asn1-func.h \
	oid.c \
	util.c util.h	


asn1-parse.c : asn1-func.h

errors.c : ksba.h
	$(srcdir)/mkerrors < $(srcdir)/ksba.h > errors.c





