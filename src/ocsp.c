/* ocsp.c - OCSP (rfc2560)
 *      Copyright (C) 2003 g10 Code GmbH
 *
 * This file is part of KSBA.
 *
 * KSBA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Fountion; either version 2 of the License, or
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "util.h"

#include "cert.h"
#include "convert.h"
#include "keyinfo.h"
#include "der-encoder.h"
#include "ber-help.h"
#include "ocsp.h"


static const char oidstr_sha1[] = "1.3.14.3.2.26";
static const char oidstr_ocsp_basic[] = "1.3.6.1.5.5.7.48.1.1";
static const char oidstr_ocsp_nonce[] = "1.3.6.1.5.5.7.48.1.2";


#if 0
static void
dump_hex (const unsigned char *p, size_t n)
{
  if (!p)
    fputs ("none", stderr);
  else
    {
      for (; n; n--, p++)
        fprintf (stderr, "%02X", *p);
    }
}
#endif


static  void
parse_skip (unsigned char const **buf, size_t *len, struct tag_info *ti)
{
  if (ti->length)
    {
      assert (ti->length <= *len);
      *len -= ti->length;
      *buf += ti->length;
    }
}

static gpg_error_t
parse_sequence (unsigned char const **buf, size_t *len, struct tag_info *ti)
{
  gpg_error_t err;

  err = _ksba_ber_parse_tl (buf, len, ti);
  if (err)
    ;
  else if (!(ti->class == CLASS_UNIVERSAL && ti->tag == TYPE_SEQUENCE
             && ti->is_constructed) )
    err = gpg_error (GPG_ERR_INV_OBJ);
  else if (ti->length > *len)
    err = gpg_error (GPG_ERR_BAD_BER);
  return err;
}

static gpg_error_t
parse_enumerated (unsigned char const **buf, size_t *len, struct tag_info *ti,
                  size_t maxlen)
{
  gpg_error_t err;

  err = _ksba_ber_parse_tl (buf, len, ti);
  if (err)
     ;
  else if (!(ti->class == CLASS_UNIVERSAL && ti->tag == TYPE_ENUMERATED
             && !ti->is_constructed) )
    err = gpg_error (GPG_ERR_INV_OBJ);
  else if (!ti->length)
    err = gpg_error (GPG_ERR_TOO_SHORT);
  else if (maxlen && ti->length > maxlen)
    err = gpg_error (GPG_ERR_TOO_LARGE);
  else if (ti->length > *len)
    err = gpg_error (GPG_ERR_BAD_BER);

  return err;
}

static gpg_error_t
parse_integer (unsigned char const **buf, size_t *len, struct tag_info *ti)
{
  gpg_error_t err;

  err = _ksba_ber_parse_tl (buf, len, ti);
  if (err)
     ;
  else if (!(ti->class == CLASS_UNIVERSAL && ti->tag == TYPE_INTEGER
             && !ti->is_constructed) )
    err = gpg_error (GPG_ERR_INV_OBJ);
  else if (!ti->length)
    err = gpg_error (GPG_ERR_TOO_SHORT);
  else if (ti->length > *len)
    err = gpg_error (GPG_ERR_BAD_BER);

  return err;
}

static gpg_error_t
parse_octet_string (unsigned char const **buf, size_t *len, struct tag_info *ti)
{
  gpg_error_t err;

  err= _ksba_ber_parse_tl (buf, len, ti);
  if (err)
    ;
  else if (!(ti->class == CLASS_UNIVERSAL && ti->tag == TYPE_OCTET_STRING
             && !ti->is_constructed) )
    err = gpg_error (GPG_ERR_INV_OBJ);
  else if (!ti->length)
    err = gpg_error (GPG_ERR_TOO_SHORT);
  else if (ti->length > *len)
    err = gpg_error (GPG_ERR_BAD_BER);

  return err;
}

static gpg_error_t
parse_object_id_into_str (unsigned char const **buf, size_t *len, char **oid)
{
  struct tag_info ti;
  gpg_error_t err;

  *oid = NULL;
  err = _ksba_ber_parse_tl (buf, len, &ti);
  if (err)
    ;
  else if (!(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OBJECT_ID
                && !ti.is_constructed) )
    err = gpg_error (GPG_ERR_INV_OBJ);
  else if (!ti.length)
    err = gpg_error (GPG_ERR_TOO_SHORT);
  else if (ti.length > *len)
    err = gpg_error (GPG_ERR_BAD_BER);
  else if (!(*oid = ksba_oid_to_str (*buf, ti.length)))
    err = gpg_error_from_errno (errno);
  else
    {
      *buf += ti.length;
      *len -= ti.length;
    }
  return err;
}


static gpg_error_t
parse_asntime_into_isotime (unsigned char const **buf, size_t *len,
                            ksba_isotime_t isotime)
{
  struct tag_info ti;
  gpg_error_t err;
 
  err = _ksba_ber_parse_tl (buf, len, &ti);
  if (err)
    ;
  else if ( !(ti.class == CLASS_UNIVERSAL
              && (ti.tag == TYPE_UTC_TIME || ti.tag == TYPE_GENERALIZED_TIME)
              && !ti.is_constructed) )
    err = gpg_error (GPG_ERR_INV_OBJ);
  else if (!(err = _ksba_asntime_to_iso (*buf, ti.length, isotime)))
    parse_skip (buf, len, &ti);
  
  return err;
}


static gpg_error_t
parse_context_tag (unsigned char const **buf, size_t *len, struct tag_info *ti,
                   int tag)
{
  gpg_error_t err;

  err = _ksba_ber_parse_tl (buf, len, ti);
  if (err)
    ;
  if (!(ti->class == CLASS_CONTEXT && ti->tag == tag && ti->is_constructed) )
    err = gpg_error (GPG_ERR_INV_OBJ);
  else if (ti->length > *len)
    err = gpg_error (GPG_ERR_BAD_BER);
  
  return err;
}



/* Create a new OCSP object and retrun it in R_OCSP.  Return 0 on
   success or an error code.
 */
gpg_error_t
ksba_ocsp_new (ksba_ocsp_t *r_ocsp)
{
  *r_ocsp = xtrycalloc (1, sizeof **r_ocsp);
  if (!*r_ocsp)
    return gpg_error_from_errno (errno);
  return 0;
}


static void
release_ocsp_certlist (struct ocsp_certlist_s *cl)
{
  while (cl)
    {
      struct ocsp_certlist_s *tmp = cl->next;
      ksba_cert_release (cl->cert);
      xfree (cl);
      cl = tmp;
    }
}


/* Release the OCSP object and all its resources. Passing NULL for
   OCSP is a valid nop. */
void
ksba_ocsp_release (ksba_ocsp_t ocsp)
{
  struct ocsp_reqitem_s *ri;
  
  if (!ocsp)
    return;
  xfree (ocsp->digest_oid);
  xfree (ocsp->request_buffer);
  for (; (ri=ocsp->requestlist); ri = ocsp->requestlist )
    {
      ocsp->requestlist = ri->next;
      ksba_cert_release (ri->cert);
      ksba_cert_release (ri->issuer_cert);
      xfree (ri->serialno);
    }
  xfree (ocsp->sigval);
  release_ocsp_certlist (ocsp->received_certs);
  xfree (ocsp);
}



/* Set the hash algorithm to be used for signing the request to OID.
   Using this function will force the creation of a signed
   request.  */
gpg_error_t
ksba_ocsp_set_digest_algo (ksba_ocsp_t ocsp, const char *oid)
{
  if (!ocsp || !oid || !*oid)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (ocsp->digest_oid)
    xfree (ocsp->digest_oid);
  ocsp->digest_oid = xtrystrdup (oid);
  if (!ocsp->digest_oid)
    return gpg_error_from_errno (errno);
  return 0;
}


gpg_error_t
ksba_ocsp_set_requestor (ksba_ocsp_t ocsp, ksba_cert_t cert)
{
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


/* Add the certificate CERT for which the status is to be requested
   and it's issuer certificate ISSUER_CERT to the context.  This
   function may be called multiple time to create a list of targets to
   get combined into one actual request. */
gpg_error_t
ksba_ocsp_add_target (ksba_ocsp_t ocsp,
                      ksba_cert_t cert, ksba_cert_t issuer_cert)
{
  struct ocsp_reqitem_s *ri;

  if (!ocsp || !cert || !issuer_cert)
    return gpg_error (GPG_ERR_INV_VALUE);
  
  ri = xtrycalloc (1, sizeof *ri);
  if (!ri)
    return gpg_error_from_errno (errno);
  ksba_cert_ref (cert);
  ri->cert = cert;
  ksba_cert_ref (issuer_cert);
  ri->issuer_cert = issuer_cert;

  ri->next = ocsp->requestlist;
  ocsp->requestlist = ri;

  return 0;
}


/* Set the nonce to be used for the request to the content of the
   buffer NONCE of size NONCELEN.  Libksba may have an upper limit of
   the allowed size of the nonce; if the supplied nonce is larger it
   will be truncated and the actual used length of the nonce returned.
   To detect the implementation limit (which should be sonsidred as a
   good suggestion), the fucntion may be called with NULL for NONCE,
   in which case the maximal usable noncelength is returned. The
   function returns the length of the nonce which will be used. */
size_t
ksba_ocsp_set_nonce (ksba_ocsp_t ocsp, unsigned char *nonce, size_t noncelen)
{
  if (!ocsp)
    return 0; 
  if (!nonce)
    return sizeof ocsp->nonce;
  if (noncelen > sizeof ocsp->nonce)
    noncelen = sizeof ocsp->nonce;
  memcpy (ocsp->nonce, nonce, noncelen);
  return noncelen;
}


/* Compute the SHA-1 nameHash for the certificate CERT and put it in
   the buffer SHA1_BUFFER which must have been allocated to at least
   20 bytes. */
static gpg_error_t
issuer_name_hash (ksba_cert_t cert, unsigned char *sha1_buffer)
{
  gpg_error_t err;
  const unsigned char *ptr;
  size_t length, dummy;

  err = _ksba_cert_get_issuer_dn_ptr (cert, &ptr, &length);
  if (!err)
    {
      err = _ksba_hash_buffer (NULL, ptr, length, 20, sha1_buffer, &dummy);
      if (!err && dummy != 20)
        err = gpg_error (GPG_ERR_BUG);
    }
  return err;
}

/* Compute the SHA-1 hash of the public key of CERT and put it in teh
   buffer SHA1_BUFFER which must have been allocated with at least 20
   bytes. */
static gpg_error_t
issuer_key_hash (ksba_cert_t cert, unsigned char *sha1_buffer)
{
  gpg_error_t err;
  const unsigned char *ptr;
  size_t length, dummy;

  err = _ksba_cert_get_public_key_ptr (cert, &ptr, &length);
  if (!err)
    {
      err = _ksba_hash_buffer (NULL, ptr, length, 20, sha1_buffer, &dummy);
      if (!err && dummy != 20)
        err = gpg_error (GPG_ERR_BUG);
    }
  return err;
}


/* Build a request from the current context.  The function checks that
   all necessary information have been set and stores the prepared
   request in the context.  A subsequent ksba_ocsp_build_request may
   then be used to retrieve this request.  Optional the requestmay be
   signed beofre calling ksba_ocsp_build_request.
 */
gpg_error_t
ksba_ocsp_prepare_request (ksba_ocsp_t ocsp)
{
  gpg_error_t err;
  struct ocsp_reqitem_s *ri;
  unsigned char *p;
  const unsigned char *der;
  size_t derlen;
  ksba_writer_t w1 = NULL;
  ksba_writer_t w2 = NULL;
  ksba_writer_t w3 = NULL;
  ksba_writer_t w4, w5, w6, w7; /* Used as aliases. */

  if (!ocsp)
    return gpg_error (GPG_ERR_INV_VALUE);

  xfree (ocsp->request_buffer);
  ocsp->request_buffer = NULL;
  ocsp->request_buflen = 0;

  if (!ocsp->requestlist)
    return gpg_error (GPG_ERR_MISSING_ACTION);

  /* Create three writer objects for construction of the request. */
  err = ksba_writer_new (&w3);
  if (!err)
    err = ksba_writer_set_mem (w3, 2048);
  if (!err)
    err = ksba_writer_new (&w2);
  if (!err)
    err = ksba_writer_new (&w1);
  if (err)
    goto leave;


  /* Loop over all single requests. */
  for (ri=ocsp->requestlist; ri; ri = ri->next)
    {
      err = ksba_writer_set_mem (w2, 256);
      if (!err)
        err = ksba_writer_set_mem (w1, 256);
      if (err)
        goto leave;

      /* Write the AlgorithmIdentifier. */
      err = _ksba_der_write_algorithm_identifier (w1, oidstr_sha1, NULL, 0);
      if (err)
        goto leave;

      /* Compute the issuerNameHash and write it into the CertID object. */
      err = issuer_name_hash (ri->issuer_cert, ri->issuer_name_hash);
      if (!err)
        err = _ksba_ber_write_tl (w1, TYPE_OCTET_STRING, CLASS_UNIVERSAL, 0,20);
      if (!err)
        err = ksba_writer_write (w1, ri->issuer_name_hash, 20);
      if(err)
        goto leave;

      /* Compute the issuerKeyHash and write it. */
      err = issuer_key_hash (ri->issuer_cert, ri->issuer_key_hash);
      if (!err)
        err = _ksba_ber_write_tl (w1, TYPE_OCTET_STRING, CLASS_UNIVERSAL, 0,20);
      if (!err)
        err = ksba_writer_write (w1, ri->issuer_key_hash, 20);
      if (err)
        goto leave;

      /* Write the serialNumber of the certificate to be checked. */
      err = _ksba_cert_get_serial_ptr (ri->cert, &der, &derlen);
      if (!err)
        err = _ksba_ber_write_tl (w1, TYPE_INTEGER, CLASS_UNIVERSAL, 0, derlen);
      if (!err)
        err = ksba_writer_write (w1, der, derlen);
      if (err)
        goto leave;
      xfree (ri->serialno);
      ri->serialno = xtrymalloc (derlen);
      if (!ri->serialno)
        err = gpg_error_from_errno (errno);
      if (err)
        goto leave;
      memcpy (ri->serialno, der, derlen);
      ri->serialnolen = derlen;


      /* Now write it out as a sequence to the outer certID object. */
      p = ksba_writer_snatch_mem (w1, &derlen);
      if (!p)
        {
          err = ksba_writer_error (w1);
          goto leave;
        }
      err = _ksba_ber_write_tl (w2, TYPE_SEQUENCE, CLASS_UNIVERSAL,
                                1, derlen);
      if (!err)
        err = ksba_writer_write (w2, p, derlen);
      xfree (p); p = NULL;
      if (err)
        goto leave;

      /* Here we would write singleRequestExtensions. */

      /* Now write it out as a sequence to the outer Request object. */
      p = ksba_writer_snatch_mem (w2, &derlen);
      if (!p)
        {
          err = ksba_writer_error (w2);
          goto leave;
        }
      err = _ksba_ber_write_tl (w3, TYPE_SEQUENCE, CLASS_UNIVERSAL,
                                1, derlen);
      if (!err)
        err = ksba_writer_write (w3, p, derlen);
      xfree (p); p = NULL;
      if (err)
        goto leave;

    } /* End of looping over single requests. */

  /* Reuse writers; for clarity, use new names. */ 
  w4 = w1; 
  w5 = w2;
  err = ksba_writer_set_mem (w4, 2048);
  if (!err)
    err = ksba_writer_set_mem (w5, 2048);
  if (err)
    goto leave;

  /* Put a sequence tag before the requestList. */
  p = ksba_writer_snatch_mem (w3, &derlen);
  if (!p)
    {
      err = ksba_writer_error (w3);
      goto leave;
    }
  err = _ksba_ber_write_tl (w4, TYPE_SEQUENCE, CLASS_UNIVERSAL,
                            1, derlen);
  if (!err)
    err = ksba_writer_write (w4, p, derlen);
  xfree (p); p = NULL;
  if (err)
    goto leave;

  
  /* Write the tbsRequest. */

  /* The version is default, thus we don't write it. */
  
  /* The requesterName would go here. */

  /* Write the requestList. */
  p = ksba_writer_snatch_mem (w4, &derlen);
  if (!p)
    {
      err = ksba_writer_error (w4);
      goto leave;
    }
  err = _ksba_ber_write_tl (w5, TYPE_SEQUENCE, CLASS_UNIVERSAL,
                            1, derlen);
  if (!err)
    err = ksba_writer_write (w5, p, derlen);
  xfree (p); p = NULL;
  if (err)
    goto leave;

  /* The requestExtensions would go here. */

  /* FIXME: Implement the nonce stuff. */

  /* Reuse writers; for clarity, use new names. */ 
  w6 = w3;
  w7 = w4;
  err = ksba_writer_set_mem (w6, 2048);
  if (!err)
    err = ksba_writer_set_mem (w7, 2048);
  if (err)
    goto leave;

  /* Prepend a sequence tag. */
  p = ksba_writer_snatch_mem (w5, &derlen);
  if (!p)
    {
      err = ksba_writer_error (w5);
      goto leave;
    }
  err = _ksba_ber_write_tl (w6, TYPE_SEQUENCE, CLASS_UNIVERSAL,
                            1, derlen);
  if (!err)
    err = ksba_writer_write (w6, p, derlen);
  xfree (p); p = NULL;
  if (err)
    goto leave;

  /* Write the ocspRequest. */

  /* Note that we do not support the optional Signature, becuase this
     saves us one writer object. */

  /* Prepend a sequence tag. */
/*   p = ksba_writer_snatch_mem (w6, &derlen); */
/*   if (!p) */
/*     { */
/*       err = ksba_writer_error (w6); */
/*       goto leave; */
/*     } */
/*   err = _ksba_ber_write_tl (w7, TYPE_SEQUENCE, CLASS_UNIVERSAL, */
/*                             1, derlen); */
/*   if (!err) */
/*     err = ksba_writer_write (w7, p, derlen); */
/*   xfree (p); p = NULL; */
/*   if (err) */
/*     goto leave; */


  /* Read out the entire request. */
  p = ksba_writer_snatch_mem (w6, &derlen);
  if (!p)
    {
      err = ksba_writer_error (w6);
      goto leave;
    }
  ocsp->request_buffer = p;
  ocsp->request_buflen = derlen;
  /* Ready. */

 leave:
  ksba_writer_release (w3);
  ksba_writer_release (w2);
  ksba_writer_release (w1);
  return err;
}


gpg_error_t 
ksba_ocsp_hash_request (ksba_ocsp_t ocsp,
                        void (*hasher)(void *, const void *,
                                       size_t length), 
                        void *hasher_arg)
{
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


gpg_error_t 
ksba_ocsp_set_sig_val (ksba_ocsp_t ocsp,
                       ksba_const_sexp_t sigval)
{
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


gpg_error_t 
ksba_ocsp_add_cert (ksba_ocsp_t ocsp, ksba_cert_t cert)
{
  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}



/* Build a request from the current context.  The function checks that
   all necessary information have been set and then returns an
   allocated buffer with the resulting request.
 */
gpg_error_t
ksba_ocsp_build_request (ksba_ocsp_t ocsp,
                         unsigned char **r_buffer, size_t *r_buflen)
{
  gpg_error_t err;

  if (!ocsp || !r_buffer || !r_buflen)
    return gpg_error (GPG_ERR_INV_VALUE);
  *r_buffer = NULL;
  *r_buflen = 0;

  if (!ocsp->requestlist)
    return gpg_error (GPG_ERR_MISSING_ACTION);
  if (!ocsp->request_buffer)
    {
      /* No prepare done, do it now. */
      err = ksba_ocsp_prepare_request (ocsp);
      if (err)
        return err;
      assert (ocsp->request_buffer);
    }
  *r_buffer = ocsp->request_buffer;
  *r_buflen = ocsp->request_buflen;
  ocsp->request_buffer = NULL;
  ocsp->request_buflen = 0;
  return 0;
}



/* Parse the first part of a response:

     OCSPResponse ::= SEQUENCE {
        responseStatus         OCSPResponseStatus,
        responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
  
     OCSPResponseStatus ::= ENUMERATED {
         successful            (0),  --Response has valid confirmations
         malformedRequest      (1),  --Illegal confirmation request
         internalError         (2),  --Internal error in issuer
         tryLater              (3),  --Try again later
                                     --(4) is not used
         sigRequired           (5),  --Must sign the request
         unauthorized          (6)   --Request unauthorized
     }
  
     ResponseBytes ::=       SEQUENCE {
         responseType   OBJECT IDENTIFIER,
         response       OCTET STRING }
  
   On success the RESPONSE_STATUS field of OCSP will be set to the
   response status and DATA will now point to the first byte in the
   octet string of the response; RLEN will be set to the length of
   this octet string.  Note thate DATALEN is also updated but might
   point to a value larger than RLEN points to, if the provided data
   is a part of a larger image. */
static gpg_error_t
parse_response_status (ksba_ocsp_t ocsp,
                       unsigned char const **data, size_t *datalen,
                       size_t *rlength)
{
  gpg_error_t err;
  struct tag_info ti;
  char *oid;

  *rlength = 0;
  /* Parse the OCSPResponse sequence. */
  err = parse_sequence (data, datalen, &ti);
  if (err)
    return err;
  /* Parse the OCSPResponseStatus. */
  err = parse_enumerated (data, datalen, &ti, 1);
  if (err)
    return err;
  switch (**data)
    {
    case 0:  ocsp->response_status = KSBA_OCSP_RSPSTATUS_SUCCESS; break;
    case 1:  ocsp->response_status = KSBA_OCSP_RSPSTATUS_MALFORMED; break;
    case 2:  ocsp->response_status = KSBA_OCSP_RSPSTATUS_INTERNAL; break;
    case 3:  ocsp->response_status = KSBA_OCSP_RSPSTATUS_TRYLATER; break;
    case 5:  ocsp->response_status = KSBA_OCSP_RSPSTATUS_SIGREQUIRED; break;
    case 6:  ocsp->response_status = KSBA_OCSP_RSPSTATUS_UNAUTHORIZED; break;
    default: ocsp->response_status = KSBA_OCSP_RSPSTATUS_OTHER; break;
    }
  parse_skip (data, datalen, &ti);

  if (ocsp->response_status)
      return 0; /* This is an error reponse; we have to stop here. */

  /* We have a successful reponse status, thus we check that
     ResponseBytes are actually available. */
  err = parse_context_tag (data, datalen, &ti, 0);
  if (err)
    return err;
  err = parse_sequence (data, datalen, &ti);
  if (err)
    return err;
  err = parse_object_id_into_str (data, datalen, &oid);
  if (err)
    return err;
  if (strcmp (oid, oidstr_ocsp_basic))
    {
      xfree (oid);
      return gpg_error (GPG_ERR_UNSUPPORTED_PROTOCOL);
    }
  xfree (oid);

  /* Check that the next field is an octet string. */
  err = parse_octet_string (data, datalen, &ti);
  if (err)
    return err;
  *rlength = ti.length;
  return 0;
}

/* Parse the object:

     SingleResponse ::= SEQUENCE {
      certID                       CertID,
      certStatus                   CertStatus,
      thisUpdate                   GeneralizedTime,
      nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
      singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }

     CertStatus ::= CHOICE {
       good        [0]     IMPLICIT NULL,
       revoked     [1]     IMPLICIT RevokedInfo,
       unknown     [2]     IMPLICIT UnknownInfo }

     RevokedInfo ::= SEQUENCE {
       revocationTime              GeneralizedTime,
       revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }

     UnknownInfo ::= NULL -- this can be replaced with an enumeration

*/

static gpg_error_t
parse_single_response (ksba_ocsp_t ocsp,
                       unsigned char const **data, size_t *datalen)
{
  gpg_error_t err;
  struct tag_info ti;
  const unsigned char *savedata;
  const unsigned char *endptr;
  size_t savedatalen;
  size_t n;
  char *oid;
  ksba_isotime_t this_update, next_update, revocation_time;
  int look_for_request;
  const unsigned char *name_hash;
  const unsigned char *key_hash;
  const unsigned char *serialno;
  size_t serialnolen;
  struct ocsp_reqitem_s *request_item = NULL;

  /* The SingeResponse sequence. */
  err = parse_sequence (data, datalen, &ti);
  if (err)
    return err;
  endptr = *data + ti.length;

  /* The CertID is
       SEQUENCE {
         hashAlgorithm       AlgorithmIdentifier,
         issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
         issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
         serialNumber        CertificateSerialNumber }
  */
  err = parse_sequence (data, datalen, &ti);
  if (err)
    return err;
  err = _ksba_parse_algorithm_identifier (*data, *datalen, &n, &oid);
  if (err)
    return err;
  assert (n <= *datalen);
  *data += n;
  *datalen -= n;
  /*   fprintf (stderr, "algorithmIdentifier is `%s'\n", oid); */
  look_for_request = !strcmp (oid, oidstr_sha1);
  xfree (oid);

  err = parse_octet_string (data, datalen, &ti);
  if (err)
    return err;
  name_hash = *data;
/*   fprintf (stderr, "issuerNameHash=");  */
/*   dump_hex (*data, ti.length); */
/*   putc ('\n', stderr); */
  if (ti.length != 20)
    look_for_request = 0; /* Can't be a SHA-1 digest. */
  parse_skip (data, datalen, &ti);

  err = parse_octet_string (data, datalen, &ti);
  if (err)
    return err;
  key_hash = *data;
/*   fprintf (stderr, "issuerKeyHash=");  */
/*   dump_hex (*data, ti.length); */
/*   putc ('\n', stderr); */
  if (ti.length != 20)
    look_for_request = 0; /* Can't be a SHA-1 digest. */
  parse_skip (data, datalen, &ti);

  err= parse_integer (data, datalen, &ti);
  if (err)
    return err;
  serialno = *data;
  serialnolen = ti.length;
/*   fprintf (stderr, "serialNumber=");  */
/*   dump_hex (*data, ti.length); */
/*   putc ('\n', stderr); */
  parse_skip (data, datalen, &ti);

  if (look_for_request)
    { 
      for (request_item = ocsp->requestlist;
           request_item; request_item = request_item->next)
        if (!memcmp (request_item->issuer_name_hash, name_hash, 20)
             && !memcmp (request_item->issuer_key_hash, key_hash, 20)
             && request_item->serialnolen == serialnolen
            && !memcmp (request_item->serialno, serialno, serialnolen))
          break; /* Got it. */
    }

  
  /* 
     CertStatus ::= CHOICE {
       good        [0]     IMPLICIT NULL,
       revoked     [1]     IMPLICIT RevokedInfo,
       unknown     [2]     IMPLICIT UnknownInfo }
  */
  *revocation_time = 0;
  err = _ksba_ber_parse_tl (data, datalen, &ti);
  if (err)
    return err;
  if (ti.length > *datalen)
    return gpg_error (GPG_ERR_BAD_BER);
  else if (ti.class == CLASS_CONTEXT && ti.tag == 0  && !ti.is_constructed)
    { /* good */
      if (!ti.length)
        ; /* Cope with zero length objects. */
      else if (*datalen && !**data)
        { /* Skip the NULL. */
          *datalen--;
          *data++;
        }
      else
        return gpg_error (GPG_ERR_INV_OBJ);

      if (request_item)
        request_item->status = KSBA_STATUS_GOOD;
    }
  else if (ti.class == CLASS_CONTEXT && ti.tag == 1  && ti.is_constructed)
    { /* revoked */
      ksba_crl_reason_t reason = KSBA_CRLREASON_UNSPECIFIED;

      err = parse_asntime_into_isotime (data, datalen, revocation_time);
      if (err)
        return err;
/*       fprintf (stderr, "revocationTime=%s\n", revocation_time); */
      savedata = *data;
      savedatalen = *datalen;
      err = parse_context_tag (data, datalen, &ti, 0);
      if (err)
        {
          *data = savedata;
          *datalen = savedatalen;
        }
      else
        { /* Got a revocationReason. */
          err = parse_enumerated (data, datalen, &ti, 1);
          if (err)
            return err;
          switch (**data)
            {
            case  0: reason = KSBA_CRLREASON_UNSPECIFIED; break;
            case  1: reason = KSBA_CRLREASON_KEY_COMPROMISE; break;
            case  2: reason = KSBA_CRLREASON_CA_COMPROMISE; break;
            case  3: reason = KSBA_CRLREASON_AFFILIATION_CHANGED; break;
            case  4: reason = KSBA_CRLREASON_SUPERSEDED; break;
            case  5: reason = KSBA_CRLREASON_CESSATION_OF_OPERATION; break;
            case  6: reason = KSBA_CRLREASON_CERTIFICATE_HOLD; break;
            case  8: reason = KSBA_CRLREASON_REMOVE_FROM_CRL; break;
            case  9: reason = KSBA_CRLREASON_PRIVILEGE_WITHDRAWN; break;
            case 10: reason = KSBA_CRLREASON_AA_COMPROMISE; break;
            default: reason = KSBA_CRLREASON_OTHER; break;
            }
          parse_skip (data, datalen, &ti);
        }
/*       fprintf (stderr, "revocationReason=%04x\n", reason); */
      if (request_item)
        {
          request_item->status = KSBA_STATUS_REVOKED;
          _ksba_copy_time (request_item->revocation_time, revocation_time);
          request_item->revocation_reason = reason;
        }
    }
  else if (ti.class == CLASS_CONTEXT && ti.tag == 2 && !ti.is_constructed
           && *datalen)
    { /* unknown */
      if (!ti.length)
        ; /* Cope with zero length objects. */
      else if (!**data)
        { /* Skip the NULL. */
          *datalen--;
          *data++;
        }
      else /* The comment indicates that an enumeration may come here. */ 
        {
          err = parse_enumerated (data, datalen, &ti, 0);
          if (err)
            return err;
          fprintf (stderr, "libksba: unknownReason with an enum of "
                   "length %u detected\n",
                   (unsigned int)ti.length);
          parse_skip (data, datalen, &ti);
        }
      if (request_item)
        request_item->status = KSBA_STATUS_UNKNOWN;
    }
  else
    err = gpg_error (GPG_ERR_INV_OBJ);

  /* thisUpdate. */
  err = parse_asntime_into_isotime (data, datalen, this_update);
  if (err)
    return err;
/*   fprintf (stderr, "thisUpdate=%s\n", this_update); */
  if (request_item)
      _ksba_copy_time (request_item->this_update, this_update);

  /* nextUpdate is optional. */
  if (*data >= endptr)
    return 0;
  *next_update = 0;
  err = _ksba_ber_parse_tl (data, datalen, &ti);
  if (err)
    return err;
  if (ti.length > *datalen)
    return gpg_error (GPG_ERR_BAD_BER);
  else if (ti.class == CLASS_CONTEXT && ti.tag == 0  && ti.is_constructed)
    { /* have nextUpdate */
      err = parse_asntime_into_isotime (data, datalen, next_update);
      if (err)
        return err;
/*       fprintf (stderr, "nextUpdate=%s\n", next_update); */
      if (request_item)
        _ksba_copy_time (request_item->next_update, next_update);
    }
  else if (ti.class == CLASS_CONTEXT && ti.tag == 1  && ti.is_constructed)
    { /* Undo that read. */
      *data -= ti.nhdr;
      *datalen += ti.nhdr;
    }
  else
    err = gpg_error (GPG_ERR_INV_OBJ);

  /* singleExtensions is optional */
  if (*data >= endptr)
    return 0;
  err = _ksba_ber_parse_tl (data, datalen, &ti);
  if (err)
    return err;
  if (ti.length > *datalen)
    return gpg_error (GPG_ERR_BAD_BER);
  if (ti.class == CLASS_CONTEXT && ti.tag == 1  && ti.is_constructed)
    {
      parse_skip (data, datalen, &ti); /* FIXME */
    }
  else
    err = gpg_error (GPG_ERR_INV_OBJ);

  return 0;
}

/* Parse the object:

        ResponseData ::= SEQUENCE {
           version              [0] EXPLICIT Version DEFAULT v1,
           responderID              ResponderID,
           producedAt               GeneralizedTime,
           responses                SEQUENCE OF SingleResponse,
           responseExtensions   [1] EXPLICIT Extensions OPTIONAL }

        ResponderID ::= CHOICE {
           byName               [1] Name,
           byKey                [2] KeyHash }


*/     
static gpg_error_t
parse_response_data (ksba_ocsp_t ocsp,
                     unsigned char const **data, size_t *datalen)
{
  gpg_error_t err;
  struct tag_info ti;
  const unsigned char *savedata;
  size_t savedatalen;
  size_t responses_length;

  /* The out er sequence. */
  err = parse_sequence (data, datalen, &ti);
  if (err)
    return err;

  /* The optional version field. */
  savedata = *data;
  savedatalen = *datalen;
  err = parse_context_tag (data, datalen, &ti, 0);
  if (err)
    {
      *data = savedata;
      *datalen = savedatalen;
    }
  else
    {
      /* FIXME: check that the version matches. */
      parse_skip (data, datalen, &ti);
    }

  /* The responderID field. */
  err = _ksba_ber_parse_tl (data, datalen, &ti);
  if (err)
    return err;
  if (ti.length > *datalen)
    return gpg_error (GPG_ERR_BAD_BER);
  else if (ti.class == CLASS_CONTEXT && ti.tag == 1  && ti.is_constructed)
    { /* byName. */
      parse_skip (data, datalen, &ti);  /* FIXME */
    }
  else if (ti.class == CLASS_CONTEXT && ti.tag == 2  && ti.is_constructed)
    { /* byKey. */
      parse_skip (data, datalen, &ti);  /* FIXME */
    }
  else
    err = gpg_error (GPG_ERR_INV_OBJ);

  /* The producedAt field. */
  err = parse_asntime_into_isotime (data, datalen, ocsp->produced_at);
  if (err)
    return err;

  /* The responses field set. */
  err = parse_sequence (data, datalen, &ti);
  if (err )
    return err;
  responses_length = ti.length;
  while (responses_length)
    {
      savedatalen = *datalen;
      err = parse_single_response (ocsp, data, datalen);
      if (err)
        return err;
      assert (responses_length >= savedatalen - *datalen);
      responses_length -= savedatalen - *datalen;
    }

  /* The optional responseExtensions set. */
  savedata = *data;
  savedatalen = *datalen;
  err = parse_context_tag (data, datalen, &ti, 1);
  if (!err)
    {
      


      /* FIXME: parse responseExtensions. */
      parse_skip (data, datalen, &ti);
    }
  else if (gpg_err_code (err) == GPG_ERR_INV_OBJ)
    {
      *data = savedata;
      *datalen = savedatalen;
    }
  else
    return err;

  return 0;
}


/* Parse the entire response message pointed to by MSG of length
   MSGLEN. */
static gpg_error_t
parse_response (ksba_ocsp_t ocsp, const unsigned char *msg, size_t msglen)
{
  gpg_error_t err;
  struct tag_info ti;
  const unsigned char *msgstart;
  const unsigned char *endptr;
  const char *s;
  size_t len;

  
  msgstart = msg;
  err = parse_response_status (ocsp, &msg, &msglen, &len);
  if (err)
    return err;
  msglen = len; /* We don't care about any extra bytes provided to us. */
  if (ocsp->response_status)
    {
/*       fprintf (stderr,"response status found to be %d - stop\n", */
/*                ocsp->response_status); */
      return 0;
    }

  /* Now that we are sure that it is a BasicOCSPResponse, we can parse
     the really important things:

     BasicOCSPResponse       ::= SEQUENCE {
     tbsResponseData      ResponseData,
     signatureAlgorithm   AlgorithmIdentifier,
     signature            BIT STRING,
     certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
  */
  err = parse_sequence (&msg, &msglen, &ti);
  if (err)
    return err;
  endptr = msg + ti.length;

  ocsp->hash_offset = msg - msgstart;
  err = parse_response_data (ocsp, &msg, &msglen);
  if (err)
    return err;
  ocsp->hash_length = msg - msgstart - ocsp->hash_offset;

  /* The signatureAlgorithm and the signature. We only need to get the
     length of both objects and let a specialized function do the
     actual parsing. */
  s = msg;
  len = msglen;
  err = parse_sequence (&msg, &msglen, &ti);
  if (err)
    return err;
  parse_skip (&msg, &msglen, &ti);
  err= _ksba_ber_parse_tl (&msg, &msglen, &ti);
  if (err)
    return err;
  if (!(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_BIT_STRING
        && !ti.is_constructed) )
    err = gpg_error (GPG_ERR_INV_OBJ);
  else if (!ti.length)
    err = gpg_error (GPG_ERR_TOO_SHORT);
  else if (ti.length > msglen)
    err = gpg_error (GPG_ERR_BAD_BER);
  parse_skip (&msg, &msglen, &ti);
  len = len - msglen;
  xfree (ocsp->sigval); ocsp->sigval = NULL;
  err =  _ksba_sigval_to_sexp (s, len, &ocsp->sigval);
  if (err)
    return err;

  /* Parse the optional sequence of certificates. */
  if (msg >= endptr)
    return 0; /* It's optional, so stop now. */
  err = parse_context_tag (&msg, &msglen, &ti, 0);
  if (gpg_err_code (err) == GPG_ERR_INV_OBJ)
    return 0; /* Not the right tag. Stop here. */
  if (err)
    return err; 
  err = parse_sequence (&msg, &msglen, &ti);
  if (err)
    return err;
  if (ti.ndef)
    return gpg_error (GPG_ERR_UNSUPPORTED_ENCODING);

  {
    ksba_cert_t cert;
    struct ocsp_certlist_s *cl, **cl_tail;

    assert (!ocsp->received_certs);
    cl_tail = &ocsp->received_certs;
    endptr = msg + ti.length;
    while (msg < endptr)
      {
        /* Find the length of the certificate. */
        s = msg;
        err = parse_sequence (&msg, &msglen, &ti);
        if (err)
          return err;
        err = ksba_cert_new (&cert);
        if (err)
          return err;
        err = ksba_cert_init_from_mem (cert, msg, ti.length);
        if (err)
          {
            ksba_cert_release (cert);
            return err;
          }
        parse_skip (&msg, &msglen, &ti);
        cl = xtrycalloc (1, sizeof *cl);
        if (!cl)
          err = gpg_error_from_errno (errno);
        if (err)
          {
            ksba_cert_release (cert);
            return gpg_error (GPG_ERR_ENOMEM);
          }
        cl->cert = cert;

        *cl_tail = cl;
        cl_tail = &ocsp->received_certs;
      }
  }

  return 0;
}


/* Given the OCSP context and a binary reponse message of MSGLEN bytes
   in MSG, this fucntion parses the response and prepares it for
   signature verification.  The status from the server is retruned in
   RESPONSE_STATUS and must be checked even if the fucntion returns
   without an error. */
gpg_error_t
ksba_ocsp_parse_response (ksba_ocsp_t ocsp,
                          const unsigned char *msg, size_t msglen,
                          ksba_ocsp_response_status_t *response_status)
{
  gpg_error_t err;
  struct ocsp_reqitem_s *ri;

  if (!ocsp || !msg || !msglen || !response_status)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!ocsp->requestlist)
    return gpg_error (GPG_ERR_MISSING_ACTION);

  ocsp->response_status = KSBA_OCSP_RSPSTATUS_NONE;
  release_ocsp_certlist (ocsp->received_certs);
  ocsp->received_certs = NULL;
  ocsp->hash_length = 0;

  /* Reset the fields used to track the reponse.  This is so that we
     can use the parse function a second time for the same
     request. This is useful in case of a TryLater response status. */
  for (ri=ocsp->requestlist; ri; ri = ri->next)
    {
      ri->status = KSBA_STATUS_NONE;
      *ri->this_update = 0;
      *ri->next_update = 0;
      *ri->revocation_time = 0;
      ri->revocation_reason = 0;
    }

  err = parse_response (ocsp, msg, msglen);
  *response_status = ocsp->response_status;

  /* FIXME: find duplicates in the request list and set them to the
     same status. */

  if (*response_status == KSBA_OCSP_RSPSTATUS_SUCCESS
      && ocsp->noncelen)
    {
      /* FIXME: Check that tehre is a rceived nonce and thit it matches. */

    }


  return err;
}


/* Return the digest algorithm to be used for the signature or NULL in
   case of an error.  The returned pointer is valid as long as the
   context is valid and no other ksba_ocsp_parse_response or
   ksba_ocsp_build_request has been used. */
const char *
ksba_ocsp_get_digest_algo (ksba_ocsp_t ocsp)
{
  return ocsp? ocsp->digest_oid : NULL;
}


/* Hash the data of the response using the hash function HASHER which
   will be passed HASHER_ARG as its first argument and a pointer and a
   length of the data to be hashed. This hash function might be called
   several times and should update the hash context.  The algorithm to
   be used for the hashing can be retrieved using
   ksba_ocsp_get_digest_algo. Note that MSG and MSGLEN should be
   indentical to the values passed to ksba_ocsp_parse_response. */
gpg_error_t
ksba_ocsp_hash_response (ksba_ocsp_t ocsp,
                         const unsigned char *msg, size_t msglen,
                         void (*hasher)(void *, const void *, size_t length), 
                         void *hasher_arg)
                         
{
  if (!ocsp || !msg || !hasher)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!ocsp->hash_length)
    return gpg_error (GPG_ERR_MISSING_ACTION);
  if (ocsp->hash_offset + ocsp->hash_length >= msglen)
    return gpg_error (GPG_ERR_CONFLICT);

  hasher (hasher_arg, msg + ocsp->hash_offset, ocsp->hash_length);
  return 0;
}


/* Return the actual signature in a format suitable to be used as
   input to Libgcrypt's verification function.  The caller must free
   the returned string and that function may be called only once after
   a successful ksba_ocsp_parse_response. Returns NULL for an invalid
   handle or if no signature is available. If PRODUCED_AT is not NULL,
   it will receive the time the response was signed. */
ksba_sexp_t
ksba_ocsp_get_sig_val (ksba_ocsp_t ocsp, ksba_isotime_t produced_at)
{
  ksba_sexp_t p;

  if (produced_at)
    *produced_at = 0;
  if (!ocsp || !ocsp->sigval )
    return NULL;

  if (produced_at)
    _ksba_copy_time (produced_at, ocsp->produced_at);

  p = ocsp->sigval;
  ocsp->sigval = NULL;
  return p;
}


/* Return the status of the certificate CERT for the last response
   done on the context OCSP.  CERT must be the same certificate as
   used for the request; only a shallow compare is done (i.e. the
   pointers are compared).  R_STATUS returns the status value,
   R_THIS_UPDATE and R_NEXT_UPDATE are the corresponding OCSP response
   values, R_REVOCATION_TIME is only set to the revocation time if the
   indicated status is revoked, R_REASON will be set to the reason
   given for a revocation.  All the R_* arguments may be given as NULL
   if the value is not required.  The function return 0 on success,
   GPG_ERR_NOT_FOUND if CERT was not used in the request or any other
   error code.  Note that the caller should have checked the signature
   of the entire reponse to be good before using the stati retruned by
   this function. */
gpg_error_t
ksba_ocsp_get_status (ksba_ocsp_t ocsp, ksba_cert_t cert,
                      ksba_status_t *r_status,
                      ksba_isotime_t r_this_update,
                      ksba_isotime_t r_next_update,
                      ksba_isotime_t r_revocation_time,
                      ksba_crl_reason_t *r_reason)
{
  struct ocsp_reqitem_s *ri;

  if (!ocsp || !cert || !r_status)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!ocsp->requestlist)
    return gpg_error (GPG_ERR_MISSING_ACTION);

  /* Find the certificate.  We don't care about the issuer certificate
     and stop at the first match.  The implementation may be optimized
     by keeping track of the last certificate found to start with the
     next one the.  Given that a usual request consiost only of a few
     certificates, this does not make much sense in reality. */
  for (ri=ocsp->requestlist; ri; ri = ri->next)
    if (ri->cert == cert)
      break;
  if (!ri)
    return gpg_error (GPG_ERR_NOT_FOUND);
  if (r_status)
    *r_status = ri->status;
  if (r_this_update)
    _ksba_copy_time (r_this_update, ri->this_update);
  if (r_next_update)
    _ksba_copy_time (r_next_update, ri->next_update);
  if (r_revocation_time)
    _ksba_copy_time (r_revocation_time, ri->revocation_time);
  if (r_reason)
    *r_reason = ri->revocation_reason;
  return 0;
}
