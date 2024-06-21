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

# Location of the released tarball archives.  This is prefixed by
# the variable RELEASE_ARCHIVE in ~/.gnupg-autogen.rc.  For example:
# RELEASE_ARCHIVE=wk@somehost:archive/tarballs
RELEASE_ARCHIVE_SUFFIX  = libksba

ACLOCAL_AMFLAGS = -I m4 -I gl/m4
DISTCHECK_CONFIGURE_FLAGS = --enable-doc

# (A suitable gitlog-to-changelog script can be found in GnuPG master.)
GITLOG_TO_CHANGELOG=gitlog-to-changelog

EXTRA_DIST = autogen.sh autogen.rc \
	     COPYING.GPLv2 COPYING.GPLv3 COPYING.LGPLv3			\
	     ChangeLog-2011 doc/ChangeLog-2011 src/ChangeLog-2011	\
	     tests/ChangeLog-2011					\
	     build-aux/libtool-patch.sed				\
	     build-aux/git-log-footer build-aux/git-log-fix


if CROSS_COMPILING
tests =
else
tests = tests
endif

if BUILD_DOC
doc = doc
else
doc =
endif

SUBDIRS = m4 gl src $(tests) $(doc)

dist-hook: gen-ChangeLog

distcheck-hook:
	set -e; ( \
	pref="#+macro: $$(echo $(PACKAGE_NAME)|tr '-' '_')_" ;\
	reldate="$$(date -u +%Y-%m-%d)" ;\
        echo "$${pref}ver  $(PACKAGE_VERSION)"  ;\
        echo "$${pref}date $${reldate}" ;\
        list='$(DIST_ARCHIVES)'; for i in $$list; do \
	  case "$$i" in *.tar.bz2) \
            echo "$${pref}size $$(wc -c <$$i|awk '{print int($$1/1024)}')k" ;\
	    echo "$${pref}sha1 $$(sha1sum <$$i|cut -d' ' -f1)" ;\
	    echo "$${pref}sha2 $$(sha256sum <$$i|cut -d' ' -f1)" ;;\
	  esac;\
	done ) | tee $(distdir).swdb


gen_start_date = 2011-12-01T00:00:00
gen-ChangeLog:
	if test -d $(top_srcdir)/.git; then				\
	  (cd $(top_srcdir) &&                      			\
	    $(GITLOG_TO_CHANGELOG) --append-dot --tear-off		\
	    --amend=build-aux/git-log-fix				\
	    --since=$(gen_start_date) ) > $(distdir)/cl-t;		\
          cat $(top_srcdir)/build-aux/git-log-footer >> $(distdir)/cl-t;\
	  rm -f $(distdir)/ChangeLog;					\
	  mv $(distdir)/cl-t $(distdir)/ChangeLog;			\
	fi



stowinstall:
	$(MAKE) $(AM_MAKEFLAGS) install prefix=/usr/local/stow/libksba



.PHONY: gen-ChangeLog clean-coverage coverage-html release sign-release

# Macro to help the release target.
RELEASE_NAME = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)

release:
	+(set -e;\
	 if [ "$(abs_top_builddir)" = "$(abs_top_srcdir)" ]; then \
           echo "error: build directory must not be the source directory" >&2;\
	   exit 2;\
         fi ;\
	 echo "/* Build started at $$(date -uIseconds) */" ;\
	 cd $(top_srcdir); \
	 ./autogen.sh --force; \
	 cd $(abs_top_builddir); \
	 rm -rf dist; mkdir dist ; cd dist ; \
	 $(abs_top_srcdir)/configure --enable-maintainer-mode; \
	 $(MAKE) distcheck; \
	 echo "/* Build finished at $$(date -uIseconds) */" ;\
         echo "/*" ;\
	 echo " * Please run the final step interactivly:" ;\
	 echo " *   make sign-release" ;\
	 echo " */" ;\
	) 2>&1 | tee "$(RELEASE_NAME).buildlog"

sign-release:
	 +(set -e; \
	  test $$(pwd | sed 's,.*/,,') = dist || cd dist; \
	  x=$$(grep '^RELEASE_ARCHIVE=' $$HOME/.gnupg-autogen.rc|cut -d= -f2);\
          if [ -z "$$x" ]; then \
             echo "error: RELEASE_ARCHIVE missing in ~/.gnupg-autogen.rc">&2; \
             exit 2;\
          fi;\
          myarchive="$$x/$(RELEASE_ARCHIVE_SUFFIX)";\
	  x=$$(grep '^RELEASE_SIGNKEY=' $$HOME/.gnupg-autogen.rc|cut -d= -f2);\
          if [ -z "$$x" ]; then \
             echo "error: RELEASE_SIGNKEY missing in ~/.gnupg-autogen.rc">&2; \
             exit 2;\
          fi;\
	  mysignkey="$$x";\
	  files1="$(RELEASE_NAME).tar.bz2" ; \
	  files2="$(RELEASE_NAME).tar.bz2.sig \
		  $(RELEASE_NAME).swdb \
		  $(RELEASE_NAME).buildlog" ;\
	  echo "/* Signing the source tarball ..." ;\
	  gpg -sbu $$mysignkey $(RELEASE_NAME).tar.bz2 ;\
	  cat $(RELEASE_NAME).swdb >swdb.snippet;\
	  echo >>swdb.snippet ;\
	  sha1sum $${files1} >>swdb.snippet ;\
          cat "../$(RELEASE_NAME).buildlog" swdb.snippet \
               | gzip >$(RELEASE_NAME).buildlog ;\
          echo "Copying to archive $$myarchive ..." ;\
	  scp -p $${files1} $${files2} $${myarchive}/ || true;\
	  echo '/*' ;\
	  echo ' * All done; for checksums see dist/swdb.snippet' ;\
	  echo ' */' ;\
	 )
