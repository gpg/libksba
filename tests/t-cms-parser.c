/* t-cms-parser.c - basic test for the CMS parser.
 *      Copyright (C) 2001 g10 Code GmbH
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

#include "t-common.h"


static int quiet;
static int verbose;


void
dummy_hash_fnc (void *arg, const void *buffer, size_t length)
{
  (void)arg;
  (void)buffer;
  (void)length;
}

static int
dummy_writer_cb (void *cb_value, const void *buffer, size_t count)
{
  (void)cb_value;
  (void)buffer;
  (void)count;
  return 0;
}



static void
one_file (const char *fname)
{
  gpg_error_t err;
  FILE *fp;
  ksba_reader_t r;
  ksba_writer_t w;
  ksba_cms_t cms;
  ksba_content_type_t ct;
  int i;
  const char *algoid;
  ksba_stop_reason_t stopreason;
  const char *s;
  size_t n;
  ksba_sexp_t p;
  char *dn;
  int idx;

  if (!quiet)
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
  /* Also create a writer so that cms.c won't return an error when
     writing processed content.  */
  err = ksba_writer_new (&w);
  if (err)
    fail_if_err (err);
  err = ksba_writer_set_cb (w, dummy_writer_cb, NULL);
  fail_if_err (err);

  switch (ksba_cms_identify (r))
    {
    case KSBA_CT_DATA:           s = "data"; break;
    case KSBA_CT_SIGNED_DATA:    s = "signed data"; break;
    case KSBA_CT_ENVELOPED_DATA: s = "enveloped data"; break;
    case KSBA_CT_AUTHENVELOPED_DATA: s = "auth enveloped data"; break;
    case KSBA_CT_DIGESTED_DATA:  s = "digested data"; break;
    case KSBA_CT_ENCRYPTED_DATA: s = "encrypted data"; break;
    case KSBA_CT_AUTH_DATA:      s = "auth data"; break;
    case KSBA_CT_SPC_IND_DATA_CTX:s = "spc indirect data context"; break;
    case KSBA_CT_OPENPGP_KEYBLOCK:s = "openpgp keyblock"; break;
    default:                     s = "unknown"; break;
    }
  if (!quiet)
    printf ("identified as: %s\n", s);

  err = ksba_cms_new (&cms);
  if (err)
    fail_if_err (err);

  err = ksba_cms_set_reader_writer (cms, r, w);
  fail_if_err (err);

  err = ksba_cms_parse (cms, &stopreason);
  fail_if_err2 (fname, err);
  if (!quiet)
    printf ("stop reason: %d\n", stopreason);

  s = ksba_cms_get_content_oid (cms, 0);
  if (!quiet)
    printf ("ContentType: %s\n", s?s:"none");

  err = ksba_cms_parse (cms, &stopreason);
  fail_if_err2 (fname, err);
  if (!quiet)
    printf ("stop reason: %d\n", stopreason);

  s = ksba_cms_get_content_oid (cms, 1);
  if (!quiet)
    {
      printf ("EncapsulatedContentType: %s\n", s?s:"none");
      printf ("DigestAlgorithms:");
    }
  for (i=0; (algoid = ksba_cms_get_digest_algo_list (cms, i)); i++)
    if (!quiet)
      printf (" %s", algoid);
  if (!quiet)
    putchar('\n');

  if (stopreason == KSBA_SR_NEED_HASH)
    if (!quiet)
      printf("Detached signature\n");

  ksba_cms_set_hash_function (cms, dummy_hash_fnc, NULL);

  do
    {
      err = ksba_cms_parse (cms, &stopreason);
      fail_if_err2 (fname, err);
      if (!quiet)
        printf ("stop reason: %d\n", stopreason);
    }
  while (stopreason != KSBA_SR_READY);


  ct = ksba_cms_get_content_type (cms, 0);
  if (ct == KSBA_CT_ENVELOPED_DATA || ct == KSBA_CT_AUTHENVELOPED_DATA)
    {
      for (idx=0; ; idx++)
        {
          err = ksba_cms_get_issuer_serial (cms, idx, &dn, &p);
          if (err == -1)
            break; /* ready */

          if (gpg_err_code (err) == GPG_ERR_UNSUPPORTED_CMS_OBJ)
            {
              printf ("recipient %d"
                      " - kekri or pwri detected\n", idx);
              err = 0;
            }
          else
            {
              fail_if_err2 (fname, err);
              if (!quiet)
                {
                  printf ("recipient %d - issuer: ", idx);
                  print_dn (dn);
                }
              ksba_free (dn);
              if (!quiet)
                {
                  putchar ('\n');
                  printf ("recipient %d - serial: ", idx);
                  print_sexp_hex (p);
                  putchar ('\n');
                }
              ksba_free (p);
            }

          dn = ksba_cms_get_enc_val (cms, idx);
          if (!quiet)
            {
              printf ("recipient %d - enc_val: ", idx);
              print_sexp (dn);
              putchar ('\n');
            }
          ksba_free (dn);
        }
    }
  else
    {
      for (idx=0; idx < 1; idx++)
        {
          err = ksba_cms_get_issuer_serial (cms, idx, &dn, &p);
          if (gpg_err_code (err) == GPG_ERR_NO_DATA && !idx)
            {
              if (!quiet)
                printf ("this is a certs-only message\n");
              break;
            }

          fail_if_err2 (fname, err);
          if (!quiet)
            {
              printf ("signer %d - issuer: ", idx);
              print_dn (dn);
              putchar ('\n');
            }
          ksba_free (dn);

          if (!quiet)
            {
              printf ("signer %d - serial: ", idx);
              print_sexp_hex (p);
              putchar ('\n');
            }
          ksba_free (p);

          err = ksba_cms_get_message_digest (cms, idx, &dn, &n);
          fail_if_err2 (fname, err);
          if (!quiet)
            {
              printf ("signer %d - messageDigest: ", idx);
              print_hex (dn, n);
              putchar ('\n');
            }
          ksba_free (dn);

          err = ksba_cms_get_sigattr_oids (cms, idx,
                                           "1.2.840.113549.1.9.3",&dn);
          if (err && err != -1)
            fail_if_err2 (fname, err);
          if (err != -1)
            {
              char *tmp;

              for (tmp=dn; *tmp; tmp++)
                if (*tmp == '\n')
                  *tmp = ' ';
              if (!quiet)
                printf ("signer %d - content-type: %s\n", idx, dn);
              ksba_free (dn);
            }

          algoid = ksba_cms_get_digest_algo (cms, idx);
          if (!quiet)
            printf ("signer %d - digest algo: %s\n", idx, algoid?algoid:"?");

          dn = ksba_cms_get_sig_val (cms, idx);
          if (dn)
            {
              if (!quiet)
                {
                  printf ("signer %d - signature: ", idx);
                  print_sexp (dn);
                  putchar ('\n');
                }
            }
          else
            {
              if (!quiet)
                printf ("signer %d - signature not found\n", idx);
            }
          ksba_free (dn);
        }
    }

  ksba_cms_release (cms);
  ksba_writer_release (w);
  ksba_reader_release (r);
  fclose (fp);
}




int
main (int argc, char **argv)
{
  if (argc)
    {
      argc--; argv++;
    }
  if (argc && !strcmp (*argv, "--verbose"))
    {
      verbose = 1;
      argc--; argv++;
    }

  if (argc)
    {
      for (; argc; argc--, argv++)
        one_file (*argv);
    }
  else
    {
      static char *testfiles[] =
        {
         "samples/detached-sig.cms",
         "samples/ecdh-sample1.p7m",
         "samples/ecdsa-sample1.p7s",
         "samples/rsa-sample1.p7m",
         "samples/rsa-sample1.p7s",
         NULL
        };
      char *fname;
      int idx;

      if (!verbose)
        quiet = 1;

      for (idx=0; testfiles[idx]; idx++)
        {
          fname = prepend_srcdir (testfiles[idx]);
          one_file (fname);
          free(fname);
        }
    }

  if (!quiet)
    printf ("*** all checks done\n");

  return 0;
}
