# Makefile.am - for the KSBA ASN.1 and X.509 library
#       Copyright (C) 2001, 2002 g10 Code GmbH
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

asn1_modules = tmttv2.asn cms.asn

EXTRA_DIST = ksba-config.in mkerrors $(asn1_modules)
BUILT_SOURCES = asn1-parse.c errors.c asn1-tables.c
DISTCLEANFILES = asn1-tables.c
bin_SCRIPTS = ksba-config
include_HEADERS = ksba.h
lib_LTLIBRARIES = libksba.la
noinst_PROGRAMS = asn1-gentables ber-dump


libksba_la_LDFLAGS = -version-info \
      @LIBKSBA_LT_CURRENT@:@LIBKSBA_LT_REVISION@:@LIBKSBA_LT_AGE@
libksba_la_INCLUDES = -I$(top_srcdir)/lib 

libksba_la_SOURCES = \
	ksba.h \
	reader.c reader.h \
	writer.c writer.h \
	asn1-parse.y asn1-parse.h \
	asn1-func.c asn1-func2.c asn1-func.h \
	ber-help.c ber-help.h \
	ber-decoder.c ber-decoder.h \
	der-encoder.c der-encoder.h \
	cert.c cert.h \
	cms.c cms.h cms-parser.c \
	crl.c crl.h \
	certreq.c certreq.h \
	keyinfo.c keyinfo.h \
	oid.c name.c dn.c time.c convert.h \
	version.c util.c util.h shared.h errors.c \
	asn1-tables.c

asn1_gentables_SOURCES = asn1-gentables.c 
asn1_gentables_LDADD = asn1-parse.o asn1-func.o oid.o util.o

ber_dump_SOURCES = ber-dump.c 
ber_dump_LDADD = ber-decoder.o ber-help.o reader.o writer.o asn1-parse.o \
	asn1-func.o oid.o util.o

asn1-parse.c : asn1-func.h

errors.c : ksba.h mkerrors
	$(srcdir)/mkerrors < $(srcdir)/ksba.h > errors.c

asn1-tables.c : asn1-gentables $(asn1_modules)
	@set -e; list=""; \
	  for file in $(asn1_modules); do list="$$list $(srcdir)/$$file";done;\
	  ./asn1-gentables $$list > asn1-tables.c	



