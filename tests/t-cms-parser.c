/* t-cms-parser.c - basic test for the CMS parser.
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
print_sexp (KsbaConstSexp p)
{
  unsigned long n;
  KsbaConstSexp endp;

  if (!p)
    fputs ("none", stdout);
  else
    {
      if (*p != '(')
        fputs ("ERROR - invalid S-exp", stdout);
      else
        {
          p++;
          n = strtoul (p, (char**)&endp, 10);
          p = endp;
          if (*p!=':')
            fputs ("ERROR - invalid value", stdout);
          else
            {
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
print_hex (unsigned char *p, size_t n)
{
  if (!p)
    fputs ("none", stdout);
  else
    {
      for (; n; n--, p++)
        printf ("%02X", *p);
    }
}


static void
one_file (const char *fname)
{
  KsbaError err;
  FILE *fp;
  KsbaReader r;
  KsbaWriter w;
  KsbaCMS cms;
  int i;
  const char *algoid;
  KsbaStopReason stopreason;
  const char *s;
  size_t n;
  KsbaSexp p;
  char *dn;
  int idx;

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

  switch (ksba_cms_identify (r))
    {
    case KSBA_CT_DATA:           s = "data"; break;
    case KSBA_CT_SIGNED_DATA:    s = "signed data"; break;
    case KSBA_CT_ENVELOPED_DATA: s = "enveloped data"; break;
    case KSBA_CT_DIGESTED_DATA:  s = "digested data"; break;
    case KSBA_CT_ENCRYPTED_DATA: s = "encrypted data"; break;
    case KSBA_CT_AUTH_DATA:      s = "auth data"; break;
    default:                     s = "unknown"; break;
    }
  printf ("identified as: %s\n", s);

  w = ksba_writer_new ();
  if (!w)
    fail_if_err (KSBA_Out_Of_Core);

  cms = ksba_cms_new ();
  if (!cms)
    fail_if_err (KSBA_Out_Of_Core);

  err = ksba_cms_set_reader_writer (cms, r, w);
  fail_if_err (err);

  err = ksba_cms_parse (cms, &stopreason);
  fail_if_err2 (fname, err);
  printf ("stop reason: %d\n", stopreason);

  s = ksba_cms_get_content_oid (cms, 0);
  printf ("ContentType: %s\n", s?s:"none");

  err = ksba_cms_parse (cms, &stopreason);
  fail_if_err2 (fname, err);
  printf ("stop reason: %d\n", stopreason);

  s = ksba_cms_get_content_oid (cms, 1);
  printf ("EncapsulatedContentType: %s\n", s?s:"none");
  printf ("DigestAlgorithms:");
  for (i=0; (algoid = ksba_cms_get_digest_algo_list (cms, i)); i++)
    printf (" %s", algoid);
  putchar('\n');

  if (stopreason == KSBA_SR_NEED_HASH)
    printf("Detached signature\n");

  err = ksba_cms_parse (cms, &stopreason);
  fail_if_err2 (fname, err);
  printf ("stop reason: %d\n", stopreason);

  if (ksba_cms_get_content_type (cms, 0) == KSBA_CT_ENVELOPED_DATA)
    {
      for (idx=0; ; idx++)
        {
          err = ksba_cms_get_issuer_serial (cms, idx, &dn, &p);
          if (err == -1)
            break; /* ready */

          fail_if_err2 (fname, err);
          printf ("recipient %d - issuer: ", idx);
          print_dn (dn);
          ksba_free (dn);
          putchar ('\n');
          printf ("recipient %d - serial: ", idx);
          print_sexp (p);
          ksba_free (p);
          putchar ('\n');
  
          dn = ksba_cms_get_enc_val (cms, idx);
          printf ("recipient %d - enc_val %s\n", idx, dn? "found": "missing");
          ksba_free (dn);
        }
    }
  else
    { 
      for (idx=0; idx < 1; idx++)
        {
          err = ksba_cms_get_issuer_serial (cms, idx, &dn, &p);
          if (err == KSBA_No_Data && !idx)
            {
              printf ("this is a certs-only message\n");
              break;
            }

          fail_if_err2 (fname, err);
          printf ("signer %d - issuer: ", idx);
          print_dn (dn);
          ksba_free (dn);
          putchar ('\n');
          printf ("signer %d - serial: ", idx);
          print_sexp (p);
          ksba_free (p);
          putchar ('\n');
  
          err = ksba_cms_get_message_digest (cms, idx, &dn, &n);
          fail_if_err2 (fname, err);
          printf ("signer %d - messageDigest: ", idx);
          print_hex (dn, n);
          ksba_free (dn);
          putchar ('\n');

          algoid = ksba_cms_get_digest_algo (cms, idx);
          printf ("signer %d - digest algo: %s\n", idx, algoid?algoid:"?");

          dn = ksba_cms_get_sig_val (cms, idx);
          printf ("signer %d - signature %s\n", idx, dn? "found": "missing");
          ksba_free (dn);
        }
    }

  ksba_cms_release (cms);
  ksba_reader_release (r);
  ksba_writer_release (w);
  fclose (fp);
}




int 
main (int argc, char **argv)
{

  if (argc > 1)
    one_file (argv[1]);
  else
    one_file ("x.ber");
  /*one_file ("pkcs7-1.ber");*/
  /*one_file ("root-cert-2.der");  should fail */

  return 0;
}



