/* t-crl-parser.c - basic test for the CRl parser.
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

#undef ENABLE_HASH_LOGGING

#ifdef ENABLE_HASH_LOGGING
#define _GNU_SOURCE 1
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <errno.h>

#include "../src/ksba.h"

#define digitp(p)   (*(p) >= '0' && *(p) <= '9')

#define fail_if_err(a) do { if(a) {                                       \
                              fprintf (stderr, "%s:%d: KSBA error: %s\n", \
                              __FILE__, __LINE__, gpg_strerror(a));   \
                              exit (1); }                              \
                           } while(0)


#define fail_if_err2(f, a) do { if(a) {\
            fprintf (stderr, "%s:%d: KSBA error on file `%s': %s\n", \
                       __FILE__, __LINE__, (f), gpg_strerror(a));   \
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



static void
print_sexp (ksba_const_sexp_t p)
{
  int level = 0;

  if (!p)
    fputs ("[none]", stdout);
  else
    {
      for (;;)
        {
          if (*p == '(')
            {
              putchar (*p);
              p++;
              level++;
            }
          else if (*p == ')')
            {
              putchar (*p);
              if (--level <= 0 )
                return;
            }
          else if (!digitp (p))
            {
              fputs ("[invalid s-exp]", stdout);
              return;
            }
          else
            {
              char *endp;
              unsigned long n;

              n = strtoul (p, &endp, 10);
              p = endp;
              if (*p != ':')
                {
                  fputs ("[invalid s-exp]", stdout);
                  return;
                }
              putchar('#');
              for (p++; n; n--, p++)
                printf ("%02X", *p);
              putchar('#');
            }
        }
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
print_time (ksba_isotime_t t)
{
  if (!t || !*t)
    fputs ("none", stdout);
  else
    printf ("%.4s-%.2s-%.2s %.2s:%.2s:%s", t, t+4, t+6, t+9, t+11, t+13);
}


static void
my_hasher (void *arg, const void *buffer, size_t length)
{
  FILE *fp = arg;

  if (fp)
    {
      if ( fwrite (buffer, length, 1, fp) != 1 )
        fail ("error writing to-be-hashed data");
    }
}




static void
one_file (const char *fname)
{
  gpg_error_t err;
  FILE *fp;
  ksba_reader_t r;
  ksba_crl_t crl;
  ksba_stop_reason_t stopreason;
  int count = 0;
  FILE *hashlog = NULL;

#ifdef ENABLE_HASH_LOGGING
    {
      char *buf;

      if (asprintf (&buf, "%s.hash.log", fname) < 0)
        fail ("asprintf failed");
      hashlog = fopen (buf, "wb");
      if (!hashlog)
        fail ("can't create log file");
      free (buf);
    }
#endif

  printf ("*** checking `%s' ***\n", fname);
  fp = fopen (fname, "r");
  if (!fp)
    {
      fprintf (stderr, "%s:%d: can't open `%s': %s\n", 
               __FILE__, __LINE__, fname, strerror (errno));
      exit (1);
    }

  err = ksba_reader_new (&r);
  if (err)
    fail_if_err (err);
  err = ksba_reader_set_file (r, fp);
  fail_if_err (err);

  err = ksba_crl_new (&crl);
  if (err)
    fail_if_err (err);

  err = ksba_crl_set_reader (crl, r);
  fail_if_err (err);

  if (hashlog)
    ksba_crl_set_hash_function (crl, my_hasher, hashlog);

  do 
    {
      err = ksba_crl_parse (crl, &stopreason);
      fail_if_err2 (fname, err);
      switch (stopreason)
        {
        case KSBA_SR_BEGIN_ITEMS:
          {
            const char *algoid;
            char *issuer;
            ksba_isotime_t this, next;

            algoid = ksba_crl_get_digest_algo (crl);
            printf ("digest algo: %s\n", algoid? algoid : "[none]");

            err = ksba_crl_get_issuer (crl, &issuer);
            fail_if_err2 (fname, err);
            printf ("issuer: ");
            print_dn (issuer);
            xfree (issuer);
            putchar ('\n');
            err = ksba_crl_get_update_times (crl, this, next);
            if (gpg_err_code (err) != GPG_ERR_INV_TIME)
              fail_if_err2 (fname, err);
            printf ("thisUpdate: ");
            print_time (this);
            putchar ('\n');
            printf ("nextUpdate: ");
            print_time (next);
            putchar ('\n');
          }
          break;

        case KSBA_SR_GOT_ITEM:
          {
            ksba_sexp_t serial;
            ksba_isotime_t rdate;
            ksba_crl_reason_t reason;

            err = ksba_crl_get_item (crl, &serial, rdate, &reason);
            fail_if_err2 (fname, err);
            printf ("CRL entry %d: s=", ++count);
            print_sexp (serial);
            printf (", t=");
            print_time (rdate);
            printf (", r=%d\n", reason);
            xfree (serial);
          }
          break;

        case KSBA_SR_END_ITEMS:
          break;

        case KSBA_SR_READY:
          break;

        default:
          fail ("unknown stop reason");
        }

    }
  while (stopreason != KSBA_SR_READY);

  if ( !ksba_crl_get_digest_algo (crl))
    fail ("digest algorithm mismatch");

  {
    ksba_sexp_t sigval;

    sigval = ksba_crl_get_sig_val (crl);
    if (!sigval)
      fail ("signature value missing");
    print_sexp (sigval);
    putchar ('\n');
    xfree (sigval);
  }

  ksba_crl_release (crl);
  ksba_reader_release (r);
  fclose (fp);
  if (hashlog)
    fclose (hashlog);
}




int 
main (int argc, char **argv)
{
  const char *srcdir = getenv ("srcdir");
  
  if (!srcdir)
    srcdir = ".";

  if (argc > 1)
    {
      for (argc--, argv++; argc; argc--, argv++)
        one_file (*argv);
    }
  else
    {
      const char *files[] = {
        "crl_testpki_testpca.der",
        NULL 
      };
      int idx;
      
      for (idx=0; files[idx]; idx++)
        {
          char *fname;

          fname = xmalloc (strlen (srcdir) + 1 + strlen (files[idx]) + 1);
          strcpy (fname, srcdir);
          strcat (fname, "/");
          strcat (fname, files[idx]);
          one_file (fname);
          xfree (fname);
        }
    }

  return 0;
}

