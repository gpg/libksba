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



static void
print_sexp (KsbaConstSexp p)
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
              KsbaConstSexp endp;
              unsigned long n;

              n = strtoul (p, (char**)&endp, 10);
              p = endp;
              if (*p != ':')
                {
                  fputs ("[invalid s-exp]", stdout);
                  return;
                }
              
              for (p++; n; n--, p++)
                printf ("%02X", *p);
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
one_file (const char *fname)
{
  KsbaError err;
  FILE *fp;
  KsbaReader r;
  KsbaCRL crl;
  KsbaStopReason stopreason;

  printf ("*** checking `%s' ***\n", fname);
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

  crl = ksba_crl_new ();
  if (!crl)
    fail_if_err (KSBA_Out_Of_Core);

  err = ksba_crl_set_reader (crl, r);
  fail_if_err (err);

  do 
    {
      err = ksba_crl_parse (crl, &stopreason);
      fail_if_err2 (fname, err);
      printf ("stop reason: %d\n", stopreason);
      switch (stopreason)
        {
        case KSBA_SR_BEGIN_ITEMS:
          {
            const char *algoid;
            char *issuer;

            algoid = ksba_crl_get_digest_algo (crl);
            printf ("digest algo: %s\n", algoid? algoid : "[none]");

            err = ksba_crl_get_issuer (crl, &issuer);
            fail_if_err2 (fname, err);
            printf ("issuer: ");
            print_dn (issuer);
            xfree (issuer);
            putchar ('\n');
          }
          break;

        case KSBA_SR_GOT_ITEM:
          {
            printf ("got an CRL entry\n");
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
    KsbaSexp sigval;

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
        "crl_test01.der",
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

