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

#define fail_if_err(a) do { if(a) {                                       \
                              fprintf (stderr, "%s:%d: KSBA error: %s\n", \
                              __FILE__, __LINE__, ksba_strerror(a));   \
                              exit (1); }                              \
                           } while(0)


#define fail_if_err2(f, a) do { if(a) {\
            fprintf (stderr, "%s:%d: KSBA error on file `%s': %s\n", \
                       __FILE__, __LINE__, (f), ksba_strerror(a));   \
                            exit (1); }                              \
                           } while(0)

#define fail(s)  do { fprintf (stderr, "%s:%d: %s\n", __FILE__,__LINE__, (s));\
                      exit (1); } while(0)

#define xfree(a)  ksba_free (a)

static void *
xmalloc (size_t n)
{
  char *p = ksba_malloc (n);
  if (!p)
    {
      fprintf (stderr, "out of core\n");
      exit (1);
    }
  return p;
}


int 
main (int argc, char **argv)
{
  char inputbuf[4096];
  int inputlen;
  char *buf;
  size_t len;
  KsbaError err;
  
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
      fail ("no regular tests yet");
    }
  else
    {
      fprintf (stderr, "usage: t-dnparser [--to-str|--to-der]\n");
      return 1;
    }

  return 0;
}

