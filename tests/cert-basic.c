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
#include "../src/keyinfo.h"

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

#define xfree(a)  ksba_free (a)

static int errorcount = 0;


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
              KsbaConstSexp endp;
              unsigned long n;

              n = strtoul (p, (char**)&endp, 10);
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
list_extensions (KsbaCert cert)
{
  KsbaError err;
  const char *oid;
  int idx, crit, is_ca, pathlen;
  size_t off, len;
  unsigned int usage;

  for (idx=0; !(err=ksba_cert_get_extension (cert, idx,
                                             &oid, &crit, &off, &len));idx++)
    {
      printf ("Extn: %s at %d with length %d %s\n",
              oid, (int)off, (int)len, crit? "(critical)":"");
    }
  if (err && err != -1 )
    {
      fprintf (stderr,
               "%s:%d: enumerating extensions failed: %s\n", 
               __FILE__, __LINE__, ksba_strerror (err));
      errorcount++;
    }

  err = ksba_cert_is_ca (cert, &is_ca, &pathlen);
  if (err)
    {
      fprintf (stderr, "%s:%d: ksba_cert_is_ca failed: %s\n", 
               __FILE__, __LINE__, ksba_strerror (err));
      errorcount++;
    }
  else if (is_ca)
    printf ("This is a CA certificate with a path length of %d\n", pathlen);

  err = ksba_cert_get_key_usage (cert, &usage);
  if (err == KSBA_No_Data)
    printf ("KeyUsage: Not specified\n");
  else if (err)
    { 
      fprintf (stderr, "%s:%d: ksba_cert_get_key_usage failed: %s\n", 
               __FILE__, __LINE__, ksba_strerror (err));
      errorcount++;
    } 
  else
    {
      fputs ("KeyUsage:", stdout);
      if ( (usage & KSBA_KEYUSAGE_DIGITAL_SIGNATURE))
        fputs (" digitalSignature", stdout);
      if ( (usage & KSBA_KEYUSAGE_NON_REPUDIATION))  
        fputs (" nonRepudiation", stdout);
      if ( (usage & KSBA_KEYUSAGE_KEY_ENCIPHERMENT)) 
        fputs (" keyEncipherment", stdout);
      if ( (usage & KSBA_KEYUSAGE_DATA_ENCIPHERMENT))
        fputs (" dataEncripherment", stdout);
      if ( (usage & KSBA_KEYUSAGE_KEY_AGREEMENT))    
        fputs (" keyAgreement", stdout);
      if ( (usage & KSBA_KEYUSAGE_KEY_CERT_SIGN))
        fputs (" certSign", stdout);
      if ( (usage & KSBA_KEYUSAGE_CRL_SIGN))  
        fputs (" crlSign", stdout);
      if ( (usage & KSBA_KEYUSAGE_ENCIPHER_ONLY))
        fputs (" encipherOnly", stdout);
      if ( (usage & KSBA_KEYUSAGE_DECIPHER_ONLY))  
        fputs (" decipherOnly", stdout);
      putchar ('\n');
    }

}


static void
one_file (const char *fname)
{
  KsbaError err;
  FILE *fp;
  KsbaReader r;
  KsbaCert cert;
  char *dn;
  time_t t;
  int idx;
  KsbaSexp sexp;

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

  sexp = ksba_cert_get_serial (cert);
  fputs ("  serial....: ", stdout);
  print_sexp (sexp);
  ksba_free (sexp);
  putchar ('\n');

  for (idx=0;(dn = ksba_cert_get_issuer (cert, idx));idx++) 
    {
      fputs (idx?"         aka: ":"  issuer....: ", stdout);
      print_dn (dn);
      ksba_free (dn);
      putchar ('\n');
    }

  for (idx=0;(dn = ksba_cert_get_subject (cert, idx));idx++) 
    {
      fputs (idx?"         aka: ":"  subject...: ", stdout);
      print_dn (dn);
      ksba_free (dn);
      putchar ('\n');
    }

  t = ksba_cert_get_validity (cert, 0);
  fputs ("  notBefore.: ", stdout);
  print_time (t);
  putchar ('\n');
  t = ksba_cert_get_validity (cert, 1);
  fputs ("  notAfter..: ", stdout);
  print_time (t);
  putchar ('\n');

  printf ("  hash algo.: %s\n", ksba_cert_get_digest_algo (cert));

  /* check that the sexp to keyinfo conversion works */
  {
    KsbaSexp public;

    public = ksba_cert_get_public_key (cert);
    if (!public)
      {
        fprintf (stderr, "%s:%d: public key not found\n", 
                 __FILE__, __LINE__);
        errorcount++;
      }
    else
      {
        unsigned char *der;
        size_t derlen;

        err = _ksba_keyinfo_from_sexp (public, &der, &derlen);
        if (err)
          {
            fprintf (stderr, "%s:%d: converting public key failed: %s\n", 
                     __FILE__, __LINE__, ksba_strerror (err));
            errorcount++;
          }
        else 
          {
            KsbaSexp tmp;

            err = _ksba_keyinfo_to_sexp (der, derlen, &tmp);
            if (err)
              {
                fprintf (stderr,
                         "%s:%d: re-converting public key failed: %s\n", 
                         __FILE__, __LINE__, ksba_strerror (err));
                errorcount++;
              }
            else
              {
                unsigned char *der2;
                size_t derlen2;

                err = _ksba_keyinfo_from_sexp (tmp, &der2, &derlen2);
                if (err)
                  {
                    fprintf (stderr, "%s:%d: re-re-converting "
                             "public key failed: %s\n", 
                             __FILE__, __LINE__, ksba_strerror (err));
                    errorcount++;
                  }
                else if (derlen != derlen2 || memcmp (der, der2, derlen))
                  {
                    fprintf (stderr, "%s:%d: mismatch after "
                             "re-re-converting public key\n", 
                             __FILE__, __LINE__);
                    errorcount++;
                    xfree (der2);
                  }
                xfree (tmp);
              }
            xfree (der);
          }
      }
  }

  list_extensions (cert);

  ksba_cert_release (cert);
  cert = ksba_cert_new ();
  if (!cert)
    fail_if_err (KSBA_Out_Of_Core);

  err = ksba_cert_read_der (cert, r);
  if (err != -1)
    {
      fprintf (stderr, "%s:%d: expected EOF but got: %s\n", 
               __FILE__, __LINE__, ksba_strerror (err));
      errorcount++;
    }

  putchar ('\n');
  ksba_cert_release (cert);
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
        "cert_dfn_pca01.der",
        "cert_dfn_pca15.der",
        "cert_g10code_test1.der",
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
          ksba_free (fname);
        }
    }

  return !!errorcount;
}

