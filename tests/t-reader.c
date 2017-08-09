/* t-reader.c - basic tests for the reader object
 *      Copyright (C) 2017 g10 Code GmbH
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

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gpg-error.h>

#include "../src/ksba.h"
#include "t-common.h"

void
test_fd(const char* path)
{
  int fd = open (path, O_RDONLY);
  gpg_error_t err = 0;
  ksba_reader_t reader;
  ksba_cert_t cert;

  if (fd < 0)
    {
      perror ("open() failed");
      exit (1);
    }

  if ((err = ksba_reader_new (&reader)))
    {
      fprintf (stderr, "ksba_reader_new() failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  if ((err = ksba_reader_set_fd (reader, fd)))
    {
      fprintf (stderr, "ksba_reader_set_fd() failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  if ((err = ksba_cert_new (&cert)))
    {
      fprintf (stderr, "ksba_cert_new() failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  if ((err = ksba_cert_read_der (cert, reader)))
    {
      fprintf(stderr, "ksba_cert_read_der() failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  ksba_cert_release (cert);
  ksba_reader_release (reader);
  close (fd);
}

void
test_file(const char* path)
{
  FILE* fp = fopen (path, "r");
  gpg_error_t err = 0;
  ksba_reader_t reader;
  ksba_cert_t cert;

  if (!fp)
    {
      perror ("fopen() failed");
      exit (1);
    }

  if ((err = ksba_reader_new (&reader)))
    {
      fprintf (stderr, "ksba_reader_new() failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  if ((err = ksba_reader_set_file (reader, fp)))
    {
      fprintf (stderr, "ksba_reader_set_fd() failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  if ((err = ksba_cert_new (&cert)))
    {
      fprintf (stderr, "ksba_cert_new() failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  if ((err = ksba_cert_read_der (cert, reader)))
    {
      fprintf(stderr, "ksba_cert_read_der() failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  ksba_cert_release (cert);
  ksba_reader_release (reader);
  fclose (fp);
}

void
test_mem(const char* path)
{
  int fd = open (path, O_RDONLY);
  gpg_error_t err = 0;
  ksba_reader_t reader;
  ksba_cert_t cert;
  char *mem = NULL;
  ssize_t ret = 0;
  size_t p = 0;
  struct stat st;

  if (fd < 0)
    {
      perror ("fopen() failed");
      exit (1);
    }

  if (fstat (fd, &st))
    {
      fprintf (stderr, "fstat() failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  mem = xmalloc(st.st_size);

  while (p < st.st_size && (ret = read(fd, mem + p, st.st_size - p)))
    {
      if (ret < 0)
        {
          fprintf (stderr, "read() failed: %s\n", gpg_strerror (err));
          exit (1);
        }
      p += ret;
    }

  if ((err = ksba_reader_new (&reader)))
    {
      exit (1);
    }

  if ((err = ksba_reader_set_mem (reader, mem, st.st_size)))
    {
      fprintf (stderr, "ksba_reader_set_mem() failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  if ((err = ksba_cert_new (&cert)))
    {
      fprintf (stderr, "ksba_cert_new() failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  if ((err = ksba_cert_read_der (cert, reader)))
    {
      fprintf(stderr, "ksba_cert_read_der() failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  ksba_cert_release (cert);
  ksba_reader_release (reader);
  xfree (mem);
  close (fd);
}

int
main (int argc, char **argv)
{
  if (argc == 1)
    {
      test_fd (prepend_srcdir ("cert_g10code_test1.der"));
      test_file (prepend_srcdir ("cert_g10code_test1.der"));
      test_mem (prepend_srcdir ("cert_g10code_test1.der"));
    }
  else
    {
      int i;
      for (i = 1; i < argc; ++i)
        {
          test_fd (argv[i]);
          test_file (argv[i]);
          test_mem (argv[i]);
        }
    }

  return 0;
}
