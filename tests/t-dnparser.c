/* t-dnparser.c - basic test for the DN parser
 *      Copyright (C) 2002 g10 Code GmbH
 *
 * This file is part of KSBA.
 *
 * KSBA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * KSBA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <errno.h>

#include "../src/ksba.h"
#include "../src/convert.h"
#include "t-common.h"



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
  char *buf;
  size_t len;

  for (i=0; empty_elements[i]; i++)
    {
      err = _ksba_dn_from_str (empty_elements[i], &buf, &len);
      if (gpg_err_code (err) != GPG_ERR_SYNTAX)
        fail ("empty element not detected");
      xfree (buf);
    }

}



int 
main (int argc, char **argv)
{
  char inputbuf[4096];
  int inputlen;
  char *buf;
  size_t len;
  gpg_error_t err;
  
  if (argc == 2 && !strcmp (argv[1], "--to-str") )
    { /* Read the DER encoed DN from stdin write the string to stdout */
      inputlen = fread (inputbuf, 1, sizeof inputbuf, stdin);
      if (!feof (stdin))
        fail ("read error or input too large");
      
      fail ("no yet implemented");

    }
  else if (argc == 2 && !strcmp (argv[1], "--to-der") )
    { /* Read the String from stdin write the DER encoding to stdout */
      inputlen = fread (inputbuf, 1, sizeof inputbuf, stdin);
      if (!feof (stdin))
        fail ("read error or input too large");
      
      err = _ksba_dn_from_str (inputbuf, &buf, &len);
      fail_if_err (err);
      fwrite (buf, len, 1, stdout);
    }
  else if (argc == 1)
    {
      test_1 ();
    }
  else
    {
      fprintf (stderr, "usage: t-dnparser [--to-str|--to-der]\n");
      return 1;
    }

  return 0;
}

