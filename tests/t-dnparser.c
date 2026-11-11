/* t-dnparser.c - basic test for the DN parser
 *      Copyright (C) 2002, 2006 g10 Code GmbH
 *
 * This file is part of KSBA.
 *
 * KSBA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * KSBA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <errno.h>

#include "../src/ksba.h"
#include "t-common.h"

static int quiet;
static int verbose;


static void
test_0 (void)
{
  static struct
  { const char *string;
    const char *canon;
  } tv[] = {
    { "C=de,O=g10 Code,OU=qa,CN=Pépé le Moko",
      "C=de,O=g10 Code,OU=qa,CN=Pépé le Moko" },
    { "C= de,  O=g10 Code , OU=qa ,CN=Pépé le Moko",
      "C=de,O=g10 Code,OU=qa,CN=Pépé le Moko" },
    { "C= de,   O=g10 Code  ,  OU=qa ,CN=Pépé le Moko",
      "C=de,O=g10 Code,OU=qa,CN=Pépé le Moko" },
    { "CN=www.gnupg.org",
      "CN=www.gnupg.org" },
    { "   CN=www.gnupg.org  ",
      "CN=www.gnupg.org"       },
    { "   CN=www.gnupg.org \\  ",
      "CN=www.gnupg.org \\ "  },
    { "   CN=www.gnupg.org \\      ",
      "CN=www.gnupg.org \\ "  },
    { "   CN=www.gnupg.org  \\ \\     ",  /* Two escaped spaces ... */
      "CN=www.gnupg.org   \\ "  },        /* -> only last escaped.  */
    { "CN=Edward Tester,OU=demo,O=g10 Code Gmbh,C=de\\ ",
      "CN=Edward Tester,OU=demo,O=g10 Code Gmbh,C=de\\ " },
    { "CN=Edward Tester,OU=demo,O=g10 Code Gmbh,C=de  \\ ",
      "CN=Edward Tester,OU=demo,O=g10 Code Gmbh,C=de  \\ " },
    { "CN=Edward Tester,OU=demo,O=g10 Code Gmbh,C=de  \\   ",
      "CN=Edward Tester,OU=demo,O=g10 Code Gmbh,C=de  \\ " },
    { "C=fr,L=Paris,CN=Julien Duvivier,EMAIL=julien@example.org",
      "C=fr,L=Paris,CN=Julien Duvivier,"
      "1.2.840.113549.1.9.1=#6A756C69656E406578616D706C652E6F7267" }
  };
  gpg_error_t err;
  int i;
  unsigned char *buf;
  size_t off, len, buflen;
  char *string;

  for (i=0; i < DIM(tv); i++)
    {
      err = ksba_dn_str2der (tv[i].string, &buf, &buflen);
      if (err)
        {
          fprintf (stderr, "%s:%d: ksba_dn_str2der failed for `%s': %s\n",
                   __FILE__,__LINE__, tv[i].string, gpg_strerror (err));
          exit (1);
        }
      err = ksba_dn_teststr (tv[i].string, 0, &off, &len);
      if (err)
        {
          fprintf (stderr, "%s:%d: ksba_dn_teststr failed for `%s': %s\n",
                   __FILE__,__LINE__, tv[i].string, gpg_strerror (err));
          exit (1);
        }
      /* Reconvert the string.  */
      err = ksba_dn_der2str (buf, buflen, &string);
      if (err)
        {
          fprintf (stderr, "%s:%d: ksba_dn_der2str failed for `%s': %s\n",
                   __FILE__,__LINE__, tv[i].string, gpg_strerror (err));
          exit (1);
        }
      if (strcmp (tv[i].canon, string))
        {
          fprintf (stderr, "%s:%d: re-converting failed\n"
                   "  want: ->%s<-\n"
                   "   got: ->%s<-\n",
                   __FILE__,__LINE__, tv[i].canon, string);
        }
      xfree (string);
      xfree (buf);
    }
}


static void
test_1 (void)
{
  static char *empty_elements[] = {
    "C=de,O=foo,OU=,CN=joe",
    "C=de,O=foo,OU= ,CN=joe",
    "C=de,O=foo,OU=\"\" ,CN=joe",
    "C=de,O=foo,OU=",
    "C=de,O=foo,OU= ",
    "C=,O=foo,OU=bar ",
    "C = ,O=foo,OU=bar ",
    "C=",
    NULL
  };
  gpg_error_t err;
  int i;
  unsigned char *buf;
  size_t off, len;

  for (i=0; empty_elements[i]; i++)
    {
      err = ksba_dn_str2der (empty_elements[i], &buf, &len);
      if (gpg_err_code (err) != GPG_ERR_SYNTAX)
        fail ("empty element not detected");
      err = ksba_dn_teststr (empty_elements[i], 0, &off, &len);
      if (!err)
        fail ("ksba_dn_teststr returned no error");
      if (!quiet)
        printf ("string ->%s<-  error at %lu.%lu expected (%.*s)\n",
                empty_elements[i], (unsigned long)off, (unsigned long)len,
                (int)len, empty_elements[i]+off);
      xfree (buf);
    }
}

static void
test_2 (void)
{
  static char *invalid_labels[] = {
    "C=de,FOO=something,O=bar",
    "Y=foo, C=baz",
    NULL
  };
  gpg_error_t err;
  int i;
  unsigned char *buf;
  size_t off, len;

  for (i=0; invalid_labels[i]; i++)
    {
      err = ksba_dn_str2der (invalid_labels[i], &buf, &len);
      if (gpg_err_code (err) != GPG_ERR_UNKNOWN_NAME)
        fail ("invalid label not detected");
      err = ksba_dn_teststr (invalid_labels[i], 0, &off, &len);
      if (!err)
        fail ("ksba_dn_test_str returned no error");
      if (!quiet)
        printf ("string ->%s<-  error at %lu.%lu expected (%.*s)\n",
                invalid_labels[i], (unsigned long)off, (unsigned long)len,
                (int)len, invalid_labels[i]+off);
      xfree (buf);
    }
}



int
main (int argc, char **argv)
{
  char inputbuf[4096];
  unsigned char *buf;
  size_t len;
  gpg_error_t err;
  char *string;

  if (argc)
    {
      argc--; argv++;
    }
  if (argc && !strcmp (*argv, "--verbose"))
    {
      verbose = 1;
      argc--; argv++;
    }

  if (argc == 1 && !strcmp (argv[0], "--to-str") )
    { /* Read the DER encoded DN from stdin write the string to stdout */
      len = fread (inputbuf, 1, sizeof inputbuf, stdin);
      if (!feof (stdin))
        fail ("read error or input too large");

      err = ksba_dn_der2str (inputbuf, len, &string);
      fail_if_err (err);
      fputs (string, stdout);
      ksba_free (string);
    }
  else if (argc == 1 && !strcmp (argv[0], "--to-der") )
    { /* Read the String from stdin write the DER encoding to stdout */
      len = fread (inputbuf, 1, sizeof inputbuf, stdin);
      if (!feof (stdin))
        fail ("read error or input too large");
      inputbuf[len] = 0;

      err = ksba_dn_str2der (inputbuf, &buf, &len);
      fail_if_err (err);
      fwrite (buf, len, 1, stdout);
    }
  else if (!argc)
    {
      if (!verbose)
        quiet = 1;
      test_0 ();
      test_1 ();
      test_2 ();
    }
  else
    {
      fprintf (stderr, "usage: t-dnparser [--to-str|--to-der]\n");
      return 1;
    }

  return 0;
}
