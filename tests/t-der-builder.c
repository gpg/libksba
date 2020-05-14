/* t-der-builder.c - Tests for the DER builder functions
 * Copyright (C) 2020 g10 Code GmbH
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

#define PGM "t-der-builder"

#include "t-common.h"


static int verbose;



static void
test_der_encoding (void)
{
  gpg_error_t err;
  ksba_der_t d;
  unsigned char *der;
  size_t derlen;

  d = ksba_der_builder_new (0);
  if (!d)
    fail ("error creating new DER builder");

  ksba_der_add_ptr (d, KSBA_CLASS_UNIVERSAL, KSBA_TYPE_NULL, NULL, 0);
  err = ksba_der_builder_get (d, &der, &derlen);
  fail_if_err (err);
  if (derlen != 2 || memcmp (der, "\x05\x00", 2))
    fail ("bad encoding");
  xfree (der);

  ksba_der_builder_reset (d);
  ksba_der_add_ptr (d, KSBA_CLASS_UNIVERSAL, KSBA_TYPE_OCTET_STRING, "123", 3);
  err = ksba_der_builder_get (d, &der, &derlen);
  fail_if_err (err);
  if (derlen != 5 || memcmp (der, "\x04\x03""123", 5))
    fail ("bad encoding");
  xfree (der);

  ksba_der_builder_reset (d);
  ksba_der_add_ptr (d, KSBA_CLASS_UNIVERSAL, 65537, "a", 1);
  err = ksba_der_builder_get (d, &der, &derlen);
  fail_if_err (err);
  if (derlen != 6 || memcmp (der, "\x1f\x84\x80\x01\x01\x61", 6))
    fail ("bad encoding");
  xfree (der);

  ksba_der_builder_reset (d);
  ksba_der_add_tag (d, KSBA_CLASS_APPLICATION, 257);
  err = ksba_der_builder_get (d, &der, &derlen);
  fail_if_err (err);
  if (derlen != 4 || memcmp (der, "\x7f\x82\x01\x80", 4))
    fail ("bad encoding");
  xfree (der);

  ksba_der_release (d);
}


static void
test_der_builder (void)
{
  gpg_error_t err;
  ksba_der_t d;
  unsigned char *der;
  size_t derlen;

  d = ksba_der_builder_new (0);
  if (!d)
    fail ("error creating new DER builder");

  ksba_der_add_tag (d, KSBA_CLASS_UNIVERSAL, KSBA_TYPE_SEQUENCE);
  ksba_der_add_oid (d, "1.2.3.4");
  ksba_der_add_tag (d, KSBA_CLASS_UNIVERSAL, KSBA_TYPE_SET);
  ksba_der_add_tag (d, KSBA_CLASS_CONTEXT, 0);
  ksba_der_add_int (d, "\x01", 1, 0);
  ksba_der_add_end (d);
  ksba_der_add_tag (d, KSBA_CLASS_CONTEXT, 42);
  ksba_der_add_int (d, "\x7f", 1, 0);  /* 127 */
  ksba_der_add_int (d, "\x7f", 1, 1);  /* Also 127 */
  ksba_der_add_int (d, "\x82", 1, 0);  /* Note: this is a negative number.  */
  ksba_der_add_int (d, "\x83", 1, 1);  /* Forces positive encoding.    */
  ksba_der_add_end (d);
  ksba_der_add_end (d);

  err = ksba_der_builder_get (d, &der, &derlen);
  fail_if_err (err);
  /* gpgrt_log_printhex (der, derlen, "DER:"); */
  if (derlen != 30
      || memcmp (der, ("\x30\x1c\x06\x03\x2a\x03\x04\x31\x15\xa0\x03\x02"
                       "\x01\x01\xbf\x2a\x0d\x02\x01\x7f\x02\x01\x7f\x02"
                       "\x01\x82\x02\x02\x00\x83"), 30))
    fail ("bad encoding");
  xfree (der);

  ksba_der_release (d);
}


int
main (int argc, char **argv)
{
  if (argc)
    {
      argc--;  argv++;
    }

  if (argc && !strcmp (*argv, "--verbose"))
    {
      verbose = 1;
      argc--; argv++;
    }


  if (!argc)
    {
      test_der_encoding ();
      test_der_builder ();
    }
  else
    {
      fputs ("usage: "PGM"\n", stderr);
      return 1;
    }

  return 0;
}
