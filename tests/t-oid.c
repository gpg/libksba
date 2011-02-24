/* t-oid.c - Test utility for the OID functions
 *      Copyright (C) 2009 g10 Code GmbH
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


static void *
read_into_buffer (FILE *fp, size_t *r_length)
{
  char *buffer;
  size_t buflen;
  size_t nread, bufsize = 0;

  *r_length = 0;
#define NCHUNK 8192
#ifdef HAVE_W32_SYSTEM
  setmode (fileno(fp), O_BINARY);
#endif
  buffer = NULL;
  buflen = 0;
  do
    {
      bufsize += NCHUNK;
      buffer = realloc (buffer, bufsize);
      if (!buffer)
        {
          perror ("realloc failed");
          exit (1);
        }

      nread = fread (buffer + buflen, 1, NCHUNK, fp);
      if (nread < NCHUNK && ferror (fp))
        {
          perror ("fread failed");
          exit (1);
        }
      buflen += nread;
    }
  while (nread == NCHUNK);
#undef NCHUNK

  *r_length = buflen;
  return buffer;
}



int
main (int argc, char **argv)
{
  char *buffer;
  size_t buflen;
  char *result;

  (void)argc;
  (void)argv;

  buffer = read_into_buffer (stdin, &buflen);
  result = ksba_oid_to_str (buffer, buflen);
  free (buffer);
  printf ("%s\n", result? result:"[malloc failed]");
  free (result);

  return 0;
}
