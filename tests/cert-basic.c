/* cert-basic.c - basic test for the certificate management.
 *      Copyright (C) 2001 g10 Code GmbH
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

static void
print_integer (unsigned char *p)
{
  unsigned long len;

  if (!p)
    fputs ("none", stdout);
  else
    {
      len = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
      for (p+=4; len; len--, p++)
        printf ("%02X", *p);
    }
}

static void
print_time (time_t t)
{

  if (!t)
    fputs ("none", stdout);
  else if ( t == (time_t)(-1) )
    fputs ("error", stdout);
  else
    {
      struct tm *tp;

      tp = gmtime (&t);
      printf ("%04d-%02d-%02d %02d:%02d:%02d",
              1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
              tp->tm_hour, tp->tm_min, tp->tm_sec);
      assert (!tp->tm_isdst);
    }
}

static void
print_dn (char *p)
{

  if (!p)
    fputs ("error", stdout);
  else
    printf ("`%s'", p);
}


static void
one_file (const char *fname)
{
  KsbaError err;
  FILE *fp;
  KsbaReader r;
  KsbaCert cert;
  unsigned char *p;
  char *dn;
  time_t t;

  fp = fopen (fname, "r");
  if (!fp)
    {
      fprintf (stderr, "%s:%d: can't open `%s': %s\n", 
               __FILE__, __LINE__, fname, strerror (errno));
      exit (1);
    }

  r = ksba_reader_new ();
  if (!r)
    fail_if_err (KSBA_Out_Of_Core);
  err = ksba_reader_set_file (r, fp);
  fail_if_err (err);

  cert = ksba_cert_new ();
  if (!cert)
    fail_if_err (KSBA_Out_Of_Core);

  err = ksba_cert_read_der (cert, r);
  fail_if_err2 (fname, err);

  printf ("Certificate in `%s':\n", fname);

  p = ksba_cert_get_serial (cert);
  fputs ("serial: ", stdout);
  print_integer (p);
  ksba_free (p);
  putchar ('\n');

  t = ksba_cert_get_validity (cert, 0);
  fputs ("notBefore: ", stdout);
  print_time (t);
  putchar ('\n');
  t = ksba_cert_get_validity (cert, 1);
  fputs ("notAfter: ", stdout);
  print_time (t);
  putchar ('\n');

  dn = ksba_cert_get_issuer (cert);
  fputs ("issuer: ", stdout);
  print_dn (dn);
  ksba_free (dn);
  putchar ('\n');

  dn = ksba_cert_get_subject (cert);
  fputs ("subject: ", stdout);
  print_dn (dn);
  ksba_free (dn);
  putchar ('\n');

  printf ("hash algo: %s\n", ksba_cert_get_digest_algo (cert));


  ksba_cert_release (cert);
  cert = ksba_cert_new ();
  if (!cert)
    fail_if_err (KSBA_Out_Of_Core);

  err = ksba_cert_read_der (cert, r);
  if (err != -1)
    {
      fprintf (stderr, "%s:%d: expected EOF but got: %s\n", 
               __FILE__, __LINE__, ksba_strerror (err));
      exit (1);
    }

  ksba_cert_release (cert);
  ksba_reader_release (r);
  fclose (fp);
}




int 
main (int argc, char **argv)
{
  if (argc > 1)
    {
      for (argc--, argv++; argc; argc--, argv++)
        one_file (*argv);
    }
  else
    {
      one_file ("cert_dfn_pca01.der"); 
      one_file ("cert_dfn_pca15.der"); 
      one_file ("cert_g10code_test1.der");
    }

  return 0;
}






