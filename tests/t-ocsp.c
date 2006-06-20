/* t-ocsp.c - Basic tests for the OCSP subsystem.
 *      Copyright (C) 2003 g10 Code GmbH
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include "../src/ksba.h"


#include "t-common.h"

int verbose;
int debug;
int no_nonce;

static unsigned char *
read_file (const char *fname, size_t *r_length)
{
  FILE *fp;
  struct stat st;
  char *buf;
  size_t buflen;
  
  fp = fopen (fname, "rb");
  if (!fp)
    {
      fprintf (stderr, "can't open `%s': %s\n", fname, strerror (errno));
      return NULL;
    }
  
  if (fstat (fileno(fp), &st))
    {
      fprintf (stderr, "can't stat `%s': %s\n", fname, strerror (errno));
      fclose (fp);
      return NULL;
    }

  buflen = st.st_size;
  buf = xmalloc (buflen+1);
  if (fread (buf, buflen, 1, fp) != 1)
    {
      fprintf (stderr, "error reading `%s': %s\n", fname, strerror (errno));
      fclose (fp);
      xfree (buf);
      return NULL;
    }
  fclose (fp);

  *r_length = buflen;
  return buf;
}



ksba_cert_t
get_one_cert (const char *fname)
{
  gpg_error_t err;
  FILE *fp;
  ksba_reader_t r;
  ksba_cert_t cert;

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

  err = ksba_cert_new (&cert);
  if (err)
    fail_if_err (err);

  err = ksba_cert_read_der (cert, r);
  fail_if_err2 (fname, err);
  return cert;
}


/* Create a request for the DER encoded certificate in the file
   CERT_FNAME and its issuer's certificate in the file
   ISSUER_CERT_FNAME. */
void
one_request (const char *cert_fname, const char *issuer_cert_fname)
{
  gpg_error_t err;
  ksba_cert_t cert = get_one_cert (cert_fname);
  ksba_cert_t issuer_cert = get_one_cert (issuer_cert_fname);
  ksba_ocsp_t ocsp;
  unsigned char *request;
  size_t requestlen;

  err = ksba_ocsp_new (&ocsp);
  fail_if_err (err);
  
  err = ksba_ocsp_add_target (ocsp, cert, issuer_cert);
  fail_if_err (err);
  ksba_cert_release (cert);
  ksba_cert_release (issuer_cert);

  if (!no_nonce)
    ksba_ocsp_set_nonce (ocsp, "ABCDEFGHIJKLMNOP", 16);

  err = ksba_ocsp_build_request (ocsp, &request, &requestlen);
  fail_if_err (err);
  ksba_ocsp_release (ocsp);

  printf ("OCSP request of length %u created\n", (unsigned int)requestlen);
  {

    FILE *fp = fopen ("a.req", "wb");
    if (!fp)
      fail ("can't create output file `a.req'");
    if (fwrite (request, requestlen, 1, fp) != 1)
      fail ("can't write output");
    fclose (fp);
  }
  
  xfree (request);
}


void 
one_response (const char *cert_fname, const char *issuer_cert_fname,
              char *response_fname)
{
  gpg_error_t err;
  ksba_ocsp_t ocsp;
  unsigned char *request, *response;
  size_t requestlen, responselen;
  ksba_cert_t cert = get_one_cert (cert_fname);
  ksba_cert_t issuer_cert = get_one_cert (issuer_cert_fname);
  ksba_ocsp_response_status_t response_status;
  const char *t;

  err = ksba_ocsp_new (&ocsp);
  fail_if_err (err);

  /* We need to build a request, so that the context is properly
     prepared for the response. */
  err = ksba_ocsp_add_target (ocsp, cert, issuer_cert);
  fail_if_err (err);
  ksba_cert_release (issuer_cert);

  err = ksba_ocsp_build_request (ocsp, &request, &requestlen);
  fail_if_err (err);
  xfree (request);

  /* Now for the response. */
  response = read_file (response_fname, &responselen);
  if (!response)
    fail ("file error");

  err = ksba_ocsp_parse_response (ocsp, response, responselen,
                                  &response_status);
  fail_if_err (err);
  switch (response_status)
    {
    case KSBA_OCSP_RSPSTATUS_SUCCESS:      t = "success"; break;
    case KSBA_OCSP_RSPSTATUS_MALFORMED:    t = "malformed"; break;  
    case KSBA_OCSP_RSPSTATUS_INTERNAL:     t = "internal error"; break;  
    case KSBA_OCSP_RSPSTATUS_TRYLATER:     t = "try later"; break;      
    case KSBA_OCSP_RSPSTATUS_SIGREQUIRED:  t = "must sign request"; break;  
    case KSBA_OCSP_RSPSTATUS_UNAUTHORIZED: t = "unautorized"; break;  
    case KSBA_OCSP_RSPSTATUS_REPLAYED:     t = "replay detected"; break;  
    case KSBA_OCSP_RSPSTATUS_OTHER:        t = "other (unknown)"; break;  
    case KSBA_OCSP_RSPSTATUS_NONE:         t = "no status"; break;
    default: fail ("impossible response_status"); break;
    }
  printf ("response status ..: %s\n", t);

  if (response_status == KSBA_OCSP_RSPSTATUS_SUCCESS)
    {
      ksba_status_t status;
      ksba_crl_reason_t reason;
      ksba_isotime_t this_update, next_update, revocation_time, produced_at;
      ksba_sexp_t sigval;

      sigval = ksba_ocsp_get_sig_val (ocsp, produced_at);
      printf ("signature value ..: ");
      print_sexp (sigval);
      printf ("\nproduced at ......: ");
      print_time (produced_at);
      putchar ('\n');

      err = ksba_ocsp_get_status (ocsp, cert,
                                  &status, this_update, next_update,
                                  revocation_time, &reason);
      fail_if_err (err);
      printf ("certificate status: %s\n",
              status == KSBA_STATUS_GOOD? "good":
              status == KSBA_STATUS_REVOKED? "revoked":
              status == KSBA_STATUS_UNKNOWN? "unknown":
              status == KSBA_STATUS_NONE? "none": "?");
      if (status == KSBA_STATUS_REVOKED)
        {
          printf ("revocation time ..: ");
          print_time (revocation_time);
          printf ("\nrevocation reason : %s\n",
                  reason == KSBA_CRLREASON_UNSPECIFIED?   "unspecified":        
                  reason == KSBA_CRLREASON_KEY_COMPROMISE? "key compromise":
                  reason == KSBA_CRLREASON_CA_COMPROMISE?   "CA compromise":
                  reason == KSBA_CRLREASON_AFFILIATION_CHANGED?
                                                       "affiliation changed":
                  reason == KSBA_CRLREASON_SUPERSEDED?   "superseeded":
                  reason == KSBA_CRLREASON_CESSATION_OF_OPERATION?
                                                      "cessation of operation": 
                  reason == KSBA_CRLREASON_CERTIFICATE_HOLD?
                                                      "certificate on hold":   
                  reason == KSBA_CRLREASON_REMOVE_FROM_CRL? "removed from CRL":
                  reason == KSBA_CRLREASON_PRIVILEGE_WITHDRAWN?
                                                       "privilege withdrawn":
                  reason == KSBA_CRLREASON_AA_COMPROMISE? "AA compromise":
                  reason == KSBA_CRLREASON_OTHER?   "other":"?");
        }
      printf ("this update ......: ");
      print_time (this_update);
      printf ("\nnext update ......: ");
      print_time (next_update);
      putchar ('\n');
    }
  

  ksba_cert_release (cert);
  ksba_ocsp_release (ocsp);
  xfree (response);
}


static gpg_error_t 
my_hash_buffer (void *arg, const char *oid,
                const void *buffer, size_t length, size_t resultsize,
                unsigned char *result, size_t *resultlen)
{
  if (oid && strcmp (oid, "1.3.14.3.2.26")) 
    return gpg_error (GPG_ERR_NOT_SUPPORTED); /* We only support SHA-1. */ 
  if (resultsize < 20)
    return gpg_error (GPG_ERR_BUFFER_TOO_SHORT);
  sha1_hash_buffer (result, buffer, length); 
  *resultlen = 20;
  return 0;
}




/* ( printf "POST / HTTP/1.0\r\nContent-Type: application/ocsp-request\r\nContent-Length: `wc -c <a.req | tr -d ' '`\r\n\r\n"; cat a.req ) |  nc -v ocsp.openvalidation.org 8088   | sed '1,/^\r$/d' >a.rsp  */


int 
main (int argc, char **argv)
{
  int last_argc = -1;
  int response_mode = 0;
  const char *srcdir = getenv ("srcdir");
  
  if (!srcdir)
    srcdir = ".";

  ksba_set_hash_buffer_function (my_hash_buffer, NULL);
 
  if (argc)
    {
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--help"))
        {
          puts (
"usage: ./t-ocsp [options] {CERTFILE ISSUERCERTFILE}\n"
"       ./t-ocsp [options] --response {CERTFILE ISSUERCERTFILE RESPONSEFILE}\n"
"\n"
"       Options are --verbose and --debug");
          exit (0);
        }
      if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--response"))
        {
          response_mode = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--no-nonce"))
        {
          no_nonce = 1;
          argc--; argv++;
        }
    }          

 
  if (response_mode)
    {
      for ( ; argc > 2; argc -=3, argv += 3)
        one_response (*argv, argv[1], argv[2]);
      if (argc)
        fputs ("warning: extra argument ignored\n", stderr);
    }
  else if (argc)
    {
      for ( ; argc > 1; argc -=2, argv += 2)
        one_request (*argv, argv[1]);
      if (argc)
        fputs ("warning: extra argument ignored\n", stderr);
    }
  else
    {
      struct {
        const char *cert_fname;
        const char *issuer_cert_fname;
        const char *response_fname;
      } files[] = {
        { "samples/ov-userrev.crt", "samples/ov-root-ca-cert.crt", NULL },
        { NULL }
      };
      int idx;
      
      for (idx=0; files[idx].cert_fname; idx++)
        {
          char *f1, *f2;

          f1 = prepend_srcdir (files[idx].cert_fname);
          f2 = prepend_srcdir (files[idx].issuer_cert_fname);
          one_request (f1, f2);
          xfree (f2);
          xfree (f1);
        }
    }
  
  return 0;
}

