/* cms.c - cryptographic message syntax main functions
 *      Copyright (C) 2001 g10 Code GmbH
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
#include "util.h"

#include "cms.h"
#include "convert.h"
#include "keyinfo.h"
#include "der-encoder.h"
#include "ber-help.h"
#include "cert.h" /* need to access cert->root and cert->image */

static KsbaError ct_parse_data (KsbaCMS cms);
static KsbaError ct_parse_signed_data (KsbaCMS cms);
static KsbaError ct_parse_enveloped_data (KsbaCMS cms);
static KsbaError ct_parse_digested_data (KsbaCMS cms);
static KsbaError ct_parse_encrypted_data (KsbaCMS cms);
static KsbaError ct_build_data (KsbaCMS cms);
static KsbaError ct_build_signed_data (KsbaCMS cms);
static KsbaError ct_build_enveloped_data (KsbaCMS cms);
static KsbaError ct_build_digested_data (KsbaCMS cms);
static KsbaError ct_build_encrypted_data (KsbaCMS cms);

static struct { 
  const char *oid;
  KsbaContentType ct;
  KsbaError (*parse_handler)(KsbaCMS);
  KsbaError (*build_handler)(KsbaCMS);
} content_handlers[] = {
  {  "1.2.840.113549.1.7.1", KSBA_CT_DATA,
     ct_parse_data   , ct_build_data                  },
  {  "1.2.840.113549.1.7.2", KSBA_CT_SIGNED_DATA,
     ct_parse_signed_data   , ct_build_signed_data    },
  {  "1.2.840.113549.1.7.3", KSBA_CT_ENVELOPED_DATA,
     ct_parse_enveloped_data, ct_build_enveloped_data },
  {  "1.2.840.113549.1.7.5", KSBA_CT_DIGESTED_DATA, 
     ct_parse_digested_data , ct_build_digested_data  },
  {  "1.2.840.113549.1.7.6", KSBA_CT_ENCRYPTED_DATA, 
     ct_parse_encrypted_data, ct_build_encrypted_data },
  {  "1.2.840.113549.1.9.16.1.2", KSBA_CT_AUTH_DATA   },
  { NULL }
};

static char oidstr_messageDigest[] = "1.2.840.113549.1.9.4";
static char oid_messageDigest[9] = "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x04";
static char oidstr_signingTime[] = "1.2.840.113549.1.9.5";
static char oid_signingTime[9] = "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x05";


/* copy all the bytes from the reader to the writer and hash them if a
   a hash function has been set.  The writer may be NULL to just do
   the hashing */
static KsbaError
read_and_hash_cont (KsbaCMS cms)
{
  KsbaError err = 0;
  unsigned long nleft;
  char buffer[4096];
  size_t n, nread;
  struct tag_info ti;

  if (cms->inner_cont_ndef)
    {
      for (;;)
        {
          err = _ksba_ber_read_tl (cms->reader, &ti);
          if (err)
            return err;
          
          if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OCTET_STRING
              && !ti.is_constructed)
            { /* next chunk */
              nleft = ti.length;
              while (nleft)
                {
                  n = nleft < sizeof (buffer)? nleft : sizeof (buffer);
                  err = ksba_reader_read (cms->reader, buffer, n, &nread);
                  if (err)
                    return err;
                  nleft -= nread;
                  if (cms->hash_fnc)
                    cms->hash_fnc (cms->hash_fnc_arg, buffer, nread); 
                  if (cms->writer)
                    err = ksba_writer_write (cms->writer, buffer, nread);
                  if (err)
                    return err;
                }
            }
          else if (ti.class == CLASS_UNIVERSAL && !ti.tag
                   && !ti.is_constructed)
            return 0; /* ready */ 
          else
            return KSBA_Encoding_Error;
        }
    }
  else
    {
      nleft = cms->inner_cont_len;
      /* first read the octet string but allow all types here */
      err = _ksba_ber_read_tl (cms->reader, &ti);
      if (err)
        return err;
      if (nleft < ti.nhdr)
        return KSBA_Encoding_Error;
      nleft -= ti.nhdr;

      while (nleft)
        {
          n = nleft < sizeof (buffer)? nleft : sizeof (buffer);
          err = ksba_reader_read (cms->reader, buffer, n, &nread);
          if (err)
            return err;
          nleft -= nread;
          if (cms->hash_fnc)
            cms->hash_fnc (cms->hash_fnc_arg, buffer, nread); 
          if (cms->writer)
            err = ksba_writer_write (cms->writer, buffer, nread);
          if (err)
            return err;
        }
    }
  return 0;
}



/* copy all the encrypted bytes from the reader to the writer.
   Handles indefinite length encoding */
static KsbaError
read_encrypted_cont (KsbaCMS cms)
{
  KsbaError err = 0;
  unsigned long nleft;
  char buffer[4096];
  size_t n, nread;

  if (cms->inner_cont_ndef)
    {
      struct tag_info ti;

      for (;;)
        {
          err = _ksba_ber_read_tl (cms->reader, &ti);
          if (err)
            return err;
          
          if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OCTET_STRING
              && !ti.is_constructed)
            { /* next chunk */
              nleft = ti.length;
              while (nleft)
                {
                  n = nleft < sizeof (buffer)? nleft : sizeof (buffer);
                  err = ksba_reader_read (cms->reader, buffer, n, &nread);
                  if (err)
                    return err;
                  nleft -= nread;
                  err = ksba_writer_write (cms->writer, buffer, nread);
                  if (err)
                    return err;
                }
            }
          else if (ti.class == CLASS_UNIVERSAL && !ti.tag
                   && !ti.is_constructed)
            return 0; /* ready */ 
          else
            return KSBA_Encoding_Error;
        }
    }
  else
    {
      nleft = cms->inner_cont_len;
      while (nleft)
        {
          n = nleft < sizeof (buffer)? nleft : sizeof (buffer);
          err = ksba_reader_read (cms->reader, buffer, n, &nread);
          if (err)
            return err;
          nleft -= nread;
          err = ksba_writer_write (cms->writer, buffer, nread);
          if (err)
            return err;
        }
    }
  return 0;
}

/* copy data from reader to writer.  Assume that it is an octet string
   and insert undefinite length headers where needed */
static KsbaError
write_encrypted_cont (KsbaCMS cms)
{
  KsbaError err = 0;
  char buffer[4096];
  size_t nread;

  /* we do it the simple way: the parts are made up from the chunks we
     got from the read function.

     Fixme: We should write the tag here, and rite a definite length
     header if everything fits into out local buffer. actually pretty
     simple to do, but I am too lazy right now. */
  while (!(err = ksba_reader_read (cms->reader, buffer,
                                   sizeof buffer, &nread)) )
    {
      err = _ksba_ber_write_tl (cms->writer, TYPE_OCTET_STRING,
                                CLASS_UNIVERSAL, 0, nread);
      if (!err)
        err = ksba_writer_write (cms->writer, buffer, nread);
      if (err)
        return err;
    }
  if (err == -1) /* write the end tag */
      err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);

  return err;
}





/**
 * ksba_cms_new:
 * 
 * Create a new and empty CMS object
 * 
 * Return value: A CMS object or NULL in case of memory problems.
 **/
KsbaCMS
ksba_cms_new (void)
{
  KsbaCMS cms;

  cms = xtrycalloc (1, sizeof *cms);
  if (!cms)
    return NULL;


  return cms;
}

/**
 * ksba_cms_release:
 * @cms: A CMS object
 * 
 * Release a CMS object.
 **/
void
ksba_cms_release (KsbaCMS cms)
{
  if (!cms)
    return;
  xfree (cms->content.oid);
  while (cms->digest_algos)
    {
      struct oidlist_s *ol = cms->digest_algos->next;
      xfree (cms->digest_algos->oid);
      xfree (cms->digest_algos);
      cms->digest_algos = ol;
    }
  while (cms->cert_list)
    {
      struct certlist_s *cl = cms->cert_list->next;
      ksba_cert_release (cms->cert_list->cert);
      xfree (cms->cert_list);
      cms->cert_list = cl;
    }
  xfree (cms->inner_cont_oid);
  xfree (cms->encr_algo_oid);
  xfree (cms->encr_iv);
  xfree (cms->data.digest);
  _ksba_asn_release_nodes (cms->signer_info.root);
  xfree (cms->signer_info.image);
  xfree (cms->signer_info.cache.digest_algo);
  _ksba_asn_release_nodes (cms->recp_info.root);
  xfree (cms->recp_info.image);
  xfree (cms->sig_val.algo);
  xfree (cms->sig_val.value);
  xfree (cms->enc_val.algo);
  xfree (cms->enc_val.value);
  xfree (cms);
}


KsbaError
ksba_cms_set_reader_writer (KsbaCMS cms, KsbaReader r, KsbaWriter w)
{
  if (!cms || !(r || w))
    return KSBA_Invalid_Value;
  if ((r && cms->reader) || (w && cms->writer) )
    return KSBA_Conflict; /* already set */
  
  cms->reader = r;
  cms->writer = w;
  return 0;
}



KsbaError
ksba_cms_parse (KsbaCMS cms, KsbaStopReason *r_stopreason)
{
  KsbaError err;
  int i;

  if (!cms || !r_stopreason)
    return KSBA_Invalid_Value;

  *r_stopreason = KSBA_SR_RUNNING;
  if (!cms->stop_reason)
    { /* Initial state: start parsing */
      err = _ksba_cms_parse_content_info (cms);
      if (err)
        return err;
      for (i=0; content_handlers[i].oid; i++)
        {
          if (!strcmp (content_handlers[i].oid, cms->content.oid))
            break;
        }
      if (!content_handlers[i].oid)
        return KSBA_Unknown_CMS_Object;
      if (!content_handlers[i].parse_handler)
        return KSBA_Unsupported_CMS_Object;
      cms->content.ct      = content_handlers[i].ct;
      cms->content.handler = content_handlers[i].parse_handler;
      cms->stop_reason = KSBA_SR_GOT_CONTENT;
    }
  else if (cms->content.handler)
    {
      err = cms->content.handler (cms);
      if (err)
        return err;
    }
  else
    return KSBA_Unsupported_CMS_Object;
  
  *r_stopreason = cms->stop_reason;
  return 0;
}

KsbaError
ksba_cms_build (KsbaCMS cms, KsbaStopReason *r_stopreason)
{
  KsbaError err;

  if (!cms || !r_stopreason)
    return KSBA_Invalid_Value;

  *r_stopreason = KSBA_SR_RUNNING;
  if (!cms->stop_reason)
    { /* Initial state: check that the content handler is known */
      if (!cms->writer)
        return KSBA_Missing_Action;
      if (!cms->content.handler)
        return KSBA_Missing_Action;
      if (!cms->inner_cont_oid)
        return KSBA_Missing_Action;
      cms->stop_reason = KSBA_SR_GOT_CONTENT;
    }
  else if (cms->content.handler)
    {
      err = cms->content.handler (cms);
      if (err)
        return err;
    }
  else
    return KSBA_Unsupported_CMS_Object;
  
  *r_stopreason = cms->stop_reason;
  return 0;
}




/* Return the content type.  A WHAT of 0 returns the real content type
   whereas a 1 returns the inner content type.
*/
KsbaContentType
ksba_cms_get_content_type (KsbaCMS cms, int what)
{
  int i;

  if (!cms)
    return 0;
  if (!what)
    return cms->content.ct;

  if (what == 1 && cms->inner_cont_oid)
    {
      for (i=0; content_handlers[i].oid; i++)
        {
          if (!strcmp (content_handlers[i].oid, cms->inner_cont_oid))
            return content_handlers[i].ct;
        }
    }
  return 0;
}


/* Return the object ID of the current cms.  This is a constant string
   valid as long as the context is valid and no new parse is
   started. */
const char *
ksba_cms_get_content_oid (KsbaCMS cms, int what)
{
  if (!cms)
    return NULL;
  if (!what)
    return cms->content.oid;
  if (what == 1)
    return cms->inner_cont_oid;
  if (what == 2)
    return cms->encr_algo_oid;
  return NULL;
}

/* copy the initialization vector into iv and its len into ivlen.
   The caller should provide a suitable large buffer */
KsbaError
ksba_cms_get_content_enc_iv (KsbaCMS cms, unsigned char *iv,
                             size_t maxivlen, size_t *ivlen)
{
  if (!cms || !iv || !ivlen)
    return KSBA_Invalid_Value;
  if (!cms->encr_ivlen)
    return KSBA_No_Data;
  if (cms->encr_ivlen > maxivlen)
    return KSBA_Buffer_Too_Short;
  memcpy (iv, cms->encr_iv, cms->encr_ivlen);
  *ivlen = cms->encr_ivlen;
  return 0;
}


/**
 * ksba_cert_get_digest_algo_list:
 * @cert: Initialized certificate object
 * @idx: enumerator
 * 
 * Figure out the the digest algorithm used for the signature and
 * return its OID.  Note that the algos returned are just hints on
 * what to hash.
 *
 * Return value: NULL for no more algorithms or a string valid as long
 * as the the cms object is valid.
 **/
const char *
ksba_cms_get_digest_algo_list (KsbaCMS cms, int idx)
{
  struct oidlist_s *ol;

  if (!cms)
    return NULL;

  for (ol=cms->digest_algos; ol && idx; ol = ol->next, idx-- )
    ;
  if (!ol)
    return NULL;
  return ol->oid;
}


/**
 * ksba_cms_get_issuer_serial:
 * @cms: CMS object
 * @idx: index number
 * @r_issuer: returns the issuer
 * @r_serial: returns the serial number
 * 
 * This functions returns the issuer and serial number either from the
 * sid or the rid elements of a CMS object.
 * 
 * Return value: 0 on success or an error code
 **/
KsbaError
ksba_cms_get_issuer_serial (KsbaCMS cms, int idx,
                            char **r_issuer, KsbaSexp *r_serial)
{
  KsbaError err;
  const char *issuer_path, *serial_path;
  AsnNode root;
  const unsigned char *image;
  AsnNode n;

  if (!cms)
    return KSBA_Invalid_Value;
  if (idx)
    return KSBA_Invalid_Index;
  if (cms->signer_info.root)
    {
      issuer_path = "SignerInfos..sid.issuerAndSerialNumber.issuer";
      serial_path = "SignerInfos..sid.issuerAndSerialNumber.serialNumber";
      root = cms->signer_info.root;
      image = cms->signer_info.image;
    }
  else if (cms->recp_info.root)
    {
      issuer_path = "RecipientInfos..ktri.rid.issuerAndSerialNumber.issuer";
      serial_path = "RecipientInfos..ktri.rid.issuerAndSerialNumber.serialNumber";
      root = cms->recp_info.root;
      image = cms->recp_info.image;
    }
  else
    return KSBA_No_Data;
  
  if (r_issuer)
    {
      n = _ksba_asn_find_node (root, issuer_path);
      if (!n || !n->down)
        return KSBA_No_Value; 
      n = n->down; /* dereference the choice node */
      
      if (n->off == -1)
        {
          fputs ("get_issuer problem at node:\n", stderr);
          _ksba_asn_node_dump_all (n, stderr);
          return KSBA_General_Error;
        }
      err = _ksba_dn_to_str (image, n, r_issuer);
      if (err)
        return err;
    }

  if (r_serial)
    {
      char numbuf[22];
      int numbuflen;
      unsigned char *p;

      /* fixme: we do not release the r_issuer stuff on error */
      n = _ksba_asn_find_node (root, serial_path);
      if (!n)
        return KSBA_No_Value; 
      
      if (n->off == -1)
        {
          fputs ("get_serial problem at node:\n", stderr);
          _ksba_asn_node_dump_all (n, stderr);
          return KSBA_General_Error;
        }

      sprintf (numbuf,"(%u:", (unsigned int)n->len);
      numbuflen = strlen (numbuf);
      p = xtrymalloc (numbuflen + n->len + 2);
      if (!p)
        return KSBA_Out_Of_Core;
      strcpy (p, numbuf);
      memcpy (p+numbuflen, image + n->off + n->nhdr, n->len);
      p[numbuflen + n->len] = ')';
      p[numbuflen + n->len + 1] = 0;
      *r_serial = p;
    }

  return 0;
}



/**
 * ksba_cms_get_digest_algo:
 * @cms: CMS object
 * @idx: index of signer
 * 
 * Figure out the the digest algorithm used by the signer @idx return
 * its OID.  This is the algorithm acually used to calculate the
 * signature.
 *
 * Return value: NULL for no such signer or a constn string valid as
 * long as the CMS object lives.
 **/
const char *
ksba_cms_get_digest_algo (KsbaCMS cms, int idx)
{
  AsnNode n;
  char *algo;

  if (!cms)
    return NULL;
  if (!cms->signer_info.root)
    return NULL;
  if (idx)
    return NULL; /* fixme: we can only handle one signer for now */

  if (cms->signer_info.cache.digest_algo)
    return cms->signer_info.cache.digest_algo;
  
  n = _ksba_asn_find_node (cms->signer_info.root,
                           "SignerInfos..digestAlgorithm.algorithm");
  algo = _ksba_oid_node_to_str (cms->signer_info.image, n);
  if (algo)
    {
      cms->signer_info.cache.digest_algo = algo;
    }
  return algo;
}


/**
 * ksba_cms_get_cert:
 * @cms: CMS object
 * @idx: enumerator
 * 
 * Get the certificate out of a CMS.  The caller should use this in a
 * loop to get all certificates.  The returned certificate is a
 * shallow copy of the original one; the caller must still use
 * ksba_cert_release() to free it.
 * 
 * Return value: A Certificate object or NULL for end of list or error
 **/
KsbaCert
ksba_cms_get_cert (KsbaCMS cms, int idx)
{
  struct certlist_s *cl;

  if (!cms || idx < 0)
    return NULL;

  for (cl=cms->cert_list; cl && idx; cl = cl->next, idx--)
    ;
  if (!cl)
    return NULL;
  ksba_cert_ref (cl->cert);
  return cl->cert;
}


/* 
   Return the extension attribute messageDigest 
*/
KsbaError
ksba_cms_get_message_digest (KsbaCMS cms, int idx,
                             char **r_digest, size_t *r_digest_len)
{ 
  AsnNode nsiginfo, n;

  if (!cms || !r_digest || !r_digest_len)
    return KSBA_Invalid_Value;
  if (!cms->signer_info.root)
    return KSBA_No_Data;
  if (idx)
    return KSBA_Not_Implemented;
  
  *r_digest = NULL;
  *r_digest_len = 0;
  nsiginfo = _ksba_asn_find_node (cms->signer_info.root,
                                  "SignerInfos..signedAttrs");
  if (!nsiginfo)
    return KSBA_Bug;

  n = _ksba_asn_find_type_value (cms->signer_info.image, nsiginfo, 0,
                                 oid_messageDigest, DIM(oid_messageDigest));
  if (!n)
    return 0; /* this is okay, because the element is optional */

  /* check that there is only one */
  if (_ksba_asn_find_type_value (cms->signer_info.image, nsiginfo, 1,
                                 oid_messageDigest, DIM(oid_messageDigest)))
    return KSBA_Duplicate_Value;

  /* the value is is a SET OF OCTECT STRING but the set must have
     excactly one OCTECT STRING.  (rfc2630 11.2) */
  if ( !(n->type == TYPE_SET_OF && n->down
         && n->down->type == TYPE_OCTET_STRING && !n->down->right))
    return KSBA_Invalid_CMS_Object;
  n = n->down;
  if (n->off == -1)
    return KSBA_Bug;

  *r_digest_len = n->len;
  *r_digest = xtrymalloc (n->len);
  if (!*r_digest)
    return KSBA_Out_Of_Core;
  memcpy (*r_digest, cms->signer_info.image + n->off + n->nhdr, n->len);
  return 0;
}


/* 
   Return the extension attribute signing time, which may be 0 for no
   signing time */
KsbaError
ksba_cms_get_signing_time (KsbaCMS cms, int idx, time_t *r_sigtime)
{ 
  AsnNode nsiginfo, n;
  time_t t;

  if (!cms || !r_sigtime)
    return KSBA_Invalid_Value;
  if (!cms->signer_info.root)
    return KSBA_No_Data;
  if (idx)
    return KSBA_Not_Implemented;
  
  *r_sigtime = 0;
  nsiginfo = _ksba_asn_find_node (cms->signer_info.root,
                                  "SignerInfos..signedAttrs");
  if (!nsiginfo)
    return 0; /* this is okay, because signedAttribs are optional */

  n = _ksba_asn_find_type_value (cms->signer_info.image, nsiginfo, 0,
                                 oid_signingTime, DIM(oid_signingTime));
  if (!n)
    return 0; /* signing time is optional */

  /* check that there is only one */
  if (_ksba_asn_find_type_value (cms->signer_info.image, nsiginfo, 1,
                                 oid_signingTime, DIM(oid_signingTime)))
    return KSBA_Duplicate_Value;

  /* the value is is a SET OF CHOICE but the set must have
     excactly one CHOICE of generalized or utctime.  (rfc2630 11.3) */
  if ( !(n->type == TYPE_SET_OF && n->down
         && (n->down->type == TYPE_GENERALIZED_TIME
             || n->down->type == TYPE_UTC_TIME)
         && !n->down->right))
    return KSBA_Invalid_CMS_Object;
  n = n->down;
  if (n->off == -1)
    return KSBA_Bug;

  t = _ksba_asntime_to_epoch (cms->signer_info.image + n->off + n->nhdr,
                              n->len);
  if (t == (time_t)-1)
    return KSBA_Invalid_Time;
  /* Because we use 0 as no signing time, we return an error if this
     is used as a real value.  If the GCHQ folks would have even
     invented by coincidence the X.509 format and used it on
     1970-01-01 we can't do much about it.*/
  if (!t)
    return KSBA_Invalid_Time;
  *r_sigtime = t;
  return 0;
}


/**
 * ksba_cms_get_sig_val:
 * @cms: CMS object
 * @idx: index of signer
 * 
 * Return the actual signature of signer @idx in a format suitable to
 * be used as input to Libgcrypt's verification function.  The caller
 * must free the returned string.
 * 
 * Return value: NULL or a string with a S-Exp.
 **/
KsbaSexp
ksba_cms_get_sig_val (KsbaCMS cms, int idx)
{
  AsnNode n, n2;
  KsbaError err;
  KsbaSexp string;

  if (!cms)
    return NULL;
  if (!cms->signer_info.root)
    return NULL;
  if (idx)
    return NULL; /* only one signer for now */

  n = _ksba_asn_find_node (cms->signer_info.root,
                           "SignerInfos..signatureAlgorithm");
  if (!n)
      return NULL;
  if (n->off == -1)
    {
      fputs ("ksba_cms_get_sig_val problem at node:\n", stderr);
      _ksba_asn_node_dump_all (n, stderr);
      return NULL;
    }

  n2 = n->right; /* point to the actual value */
  err = _ksba_sigval_to_sexp (cms->signer_info.image + n->off,
                              n->nhdr + n->len
                              + ((!n2||n2->off == -1)? 0:(n2->nhdr+n2->len)),
                              &string);
  if (err)
      return NULL;

  return string;
}


/**
 * ksba_cms_get_enc_val:
 * @cms: CMS object
 * @idx: index of recipient info
 * 
 * Return the encrypted value (the session key) of recipient @idx in a
 * format suitable to be used as input to Libgcrypt's verification
 * function.  The caller must free the returned string.
 * 
 * Return value: NULL or a string with a S-Exp.
 **/
KsbaSexp
ksba_cms_get_enc_val (KsbaCMS cms, int idx)
{
  AsnNode n, n2;
  KsbaError err;
  KsbaSexp string;

  if (!cms)
    return NULL;
  if (!cms->recp_info.root)
    return NULL;
  if (idx)
    return NULL; /* we can only handle one recipient for now */

  n = _ksba_asn_find_node (cms->recp_info.root,
                           "RecipientInfos..ktri.keyEncryptionAlgorithm");
  if (!n)
      return NULL;
  if (n->off == -1)
    {
      fputs ("ksba_cms_get_enc_val problem at node:\n", stderr);
      _ksba_asn_node_dump_all (n, stderr);
      return NULL;
    }

  n2 = n->right; /* point to the actual value */
  err = _ksba_encval_to_sexp (cms->recp_info.image + n->off,
                              n->nhdr + n->len
                              + ((!n2||n2->off == -1)? 0:(n2->nhdr+n2->len)),
                              &string);
  if (err)
      return NULL;

  return string;
}





/* Provide a hash function so that we are able to hash the data */
void
ksba_cms_set_hash_function (KsbaCMS cms,
                            void (*hash_fnc)(void *, const void *, size_t),
                            void *hash_fnc_arg)
{
  if (cms)
    {
      cms->hash_fnc = hash_fnc;
      cms->hash_fnc_arg = hash_fnc_arg;
    }
}


/* hash the signed attributes of the given signer */
KsbaError
ksba_cms_hash_signed_attrs (KsbaCMS cms, int idx)
{
  AsnNode n;

  if (!cms)
    return KSBA_Invalid_Value;
  if (!cms->hash_fnc)
    return KSBA_Missing_Action;
  if (idx)
    return -1;
      

  n = _ksba_asn_find_node (cms->signer_info.root,
                           "SignerInfos..signedAttrs");
  if (!n || n->off == -1)
    return KSBA_No_Value; 

  /* We don't hash the implicit tag [0] but a SET tag */
  cms->hash_fnc (cms->hash_fnc_arg, "\x31", 1); 
  cms->hash_fnc (cms->hash_fnc_arg,
                 cms->signer_info.image + n->off + 1, n->nhdr + n->len - 1);

  return 0;
}


/* 
  Code to create CMS structures
*/


/**
 * ksba_cms_set_content_type:
 * @cms: A CMS object
 * @what: 0 for content type, 1 for inner content type
 * @type: Tyep constant
 * 
 * Set the content type used for build operations.  This should be the
 * first operation before starting to create a CMS message.
 * 
 * Return value: 0 on success or an error code
 **/
KsbaError
ksba_cms_set_content_type (KsbaCMS cms, int what, KsbaContentType type)
{
  int i;
  char *oid;

  if (!cms || what < 0 || what > 1 )
    return KSBA_Invalid_Value;

  for (i=0; content_handlers[i].oid; i++)
    {
      if (content_handlers[i].ct == type)
        break;
    }
  if (!content_handlers[i].oid)
    return KSBA_Unknown_CMS_Object;
  if (!content_handlers[i].build_handler)
    return KSBA_Unsupported_CMS_Object;
  oid = xtrystrdup (content_handlers[i].oid);
  if (!oid)
    return KSBA_Out_Of_Core;

  if (!what)
    {
      cms->content.oid     = oid;
      cms->content.ct      = content_handlers[i].ct;
      cms->content.handler = content_handlers[i].build_handler;
    }
  else
    {
      cms->inner_cont_oid = oid;
    }

  return 0;
}


/**
 * ksba_cms_add_digest_algo:
 * @cms:  A CMS object 
 * @oid: A stringified object OID describing the hash algorithm
 * 
 * Set the algorithm to be used for creating the hash. Note, that we
 * currently can't do a per-signer hash.
 * 
 * Return value: o on success or an error code
 **/
KsbaError
ksba_cms_add_digest_algo (KsbaCMS cms, const char *oid)
{
  struct oidlist_s *ol;

  if (!cms || !oid)
    return KSBA_Invalid_Value;

  ol = xtrymalloc (sizeof *ol);
  if (!ol)
    return KSBA_Out_Of_Core;
  
  ol->oid = xtrystrdup (oid);
  if (!ol->oid)
    {
      xfree (ol);
      return KSBA_Out_Of_Core;
    }
  ol->next = cms->digest_algos;
  cms->digest_algos = ol;
  return 0;
}


/**
 * ksba_cms_add_signer:
 * @cms: A CMS object
 * @cert: A certificate used to describe the signer.
 * 
 * This functions starts assembly of a new signed data content or adds
 * another signer to the list of signers.
 *
 * Note: after successful completion of this function ownership of
 * @cert is transferred to @cms.  
 * 
 * Return value: 0 on success or an error code.
 **/
KsbaError
ksba_cms_add_signer (KsbaCMS cms, KsbaCert cert)
{
  struct certlist_s *cl;

  if (!cms)
    return KSBA_Invalid_Value;
  
  cl = xtrycalloc (1,sizeof *cl);
  if (!cl)
      return KSBA_Out_Of_Core;

  ksba_cert_ref (cert);
  cl->cert = cert;
  cl->next = cms->cert_list;
  cms->cert_list = cl;
  return 0;
}



/**
 * ksba_cms_set_message_digest:
 * @cms: A CMS object
 * @idx: The index of the signer
 * @digest: a message digest
 * @digest_len: the length of the message digest
 * 
 * Set a message digest into the signedAttributes of the signer with
 * the index IDX.  The index of a signer is determined by the sequence
 * of ksba_cms_add_signer() calls; the first signer has the index 0.
 * This function is to be used when the hash value of the data has
 * been calculated and before the create function requests the sign
 * operation.
 * 
 * Return value: 0 on success or an error code
 **/
KsbaError
ksba_cms_set_message_digest (KsbaCMS cms, int idx, 
                             const char *digest, size_t digest_len)
{ 
  struct certlist_s *cl;

  if (!cms || !digest)
    return KSBA_Invalid_Value;
  if (!digest_len || digest_len > DIM(cl->msg_digest))
    return KSBA_Invalid_Value;
  if (idx < 0)
    return KSBA_Invalid_Index;

  for (cl=cms->cert_list; cl && idx; cl = cl->next, idx--)
    ;
  if (!cl)
    return KSBA_Invalid_Index; /* no certificate to store it */
  cl->msg_digest_len = digest_len;
  memcpy (cl->msg_digest, digest, digest_len);
  return 0;
}

/**
 * ksba_cms_set_signing_time:
 * @cms: A CMS object
 * @idx: The index of the signer
 * @sigtime: a time or 0 to use the current time
 * 
 * Set a signing time into the signedAttributes of the signer with
 * the index IDX.  The index of a signer is determined by the sequence
 * of ksba_cms_add_signer() calls; the first signer has the index 0.
 * 
 * Return value: 0 on success or an error code
 **/
KsbaError
ksba_cms_set_signing_time (KsbaCMS cms, int idx, time_t sigtime)
{ 
  struct certlist_s *cl;

  if (!cms)
    return KSBA_Invalid_Value;
  if (idx < 0)
    return KSBA_Invalid_Index;

  for (cl=cms->cert_list; cl && idx; cl = cl->next, idx--)
    ;
  if (!cl)
    return KSBA_Invalid_Index; /* no certificate to store it */
  
  if (!sigtime)
    sigtime = time (NULL);

  cl->signing_time = sigtime;
  return 0;
}

/*
 * r_sig  = (sig-val
 *	      (<algo>
 *		(<param_name1> <mpi>)
 *		...
 *		(<param_namen> <mpi>)
 *	      ))
 * The sexp must be in canocial form 
*/
KsbaError
ksba_cms_set_sig_val (KsbaCMS cms, int idx, KsbaConstSexp sigval)
{
  const char *s, *endp;
  unsigned long n;

  if (!cms)
    return KSBA_Invalid_Value;
  if (idx)
    return KSBA_Invalid_Index; /* only one signer for now */

  s = sigval;
  if (*s != '(')
    return KSBA_Invalid_Sexp;
  s++;

  n = strtoul (s, (char**)&endp, 10);
  s = endp;
  if (!n || *s!=':')
    return KSBA_Invalid_Sexp; /* we don't allow empty lengths */
  s++;
  if (n != 7 || memcmp (s, "sig-val", 7))
    return KSBA_Unknown_Sexp;
  s += 7;
  if (*s != '(')
    return digitp (s)? KSBA_Unknown_Sexp : KSBA_Invalid_Sexp;
  s++;

  /* break out the algorithm ID */
  n = strtoul (s, (char**)&endp, 10);
  s = endp;
  if (!n || *s != ':')
    return KSBA_Invalid_Sexp; /* we don't allow empty lengths */
  s++;
  xfree (cms->sig_val.algo);
  cms->sig_val.algo = xtrymalloc (n+1);
  if (!cms->sig_val.algo)
    return KSBA_Out_Of_Core;
  memcpy (cms->sig_val.algo, s, n);
  cms->sig_val.algo[n] = 0;
  s += n;

  /* And now the values - FIXME: For now we only support one */
  /* fixme: start loop */
  if (*s != '(')
    return digitp (s)? KSBA_Unknown_Sexp : KSBA_Invalid_Sexp;
  s++;
  n = strtoul (s, (char**)&endp, 10);
  s = endp;
  if (!n || *s != ':')
    return KSBA_Invalid_Sexp; 
  s++;
  s += n; /* ignore the name of the parameter */
  
  if (!digitp(s))
    return KSBA_Unknown_Sexp; /* but may also be an invalid one */
  n = strtoul (s, (char**)&endp, 10);
  s = endp;
  if (!n || *s != ':')
    return KSBA_Invalid_Sexp; 
  s++;
  xfree (cms->sig_val.value);
  cms->sig_val.value = xtrymalloc (n);
  if (!cms->sig_val.value)
    return KSBA_Out_Of_Core;
  memcpy (cms->sig_val.value, s, n);
  cms->sig_val.valuelen = n;
  s += n;
  if ( *s != ')')
    return KSBA_Unknown_Sexp; /* but may also be an invalid one */
  s++;
  /* fixme: end loop over parameters */

  /* we need 2 closing parenthesis */
  if ( *s != ')' || s[1] != ')')
    return KSBA_Invalid_Sexp; 

  return 0;
}


/* Set the conetnt encryption algorithm to OID and optionally set the
   initialization vector to IV */
KsbaError
ksba_cms_set_content_enc_algo (KsbaCMS cms,
                               const char *oid,
                               const unsigned char *iv, size_t ivlen)
{
  if (!cms || !oid)
    return KSBA_Invalid_Value;

  xfree (cms->encr_iv);
  cms->encr_iv = NULL;
  cms->encr_ivlen = 0;

  cms->encr_algo_oid = xtrystrdup (oid);
  if (!cms->encr_algo_oid)
    return KSBA_Out_Of_Core;

  if (iv)
    {
      cms->encr_iv = xtrymalloc (ivlen);
      if (!cms->encr_iv)
        return KSBA_Out_Of_Core;
      memcpy (cms->encr_iv, iv, ivlen);
      cms->encr_ivlen = ivlen;
    }
  return 0;
}


/* 
 * encval is expected to be a canonical encoded  S-Exp of this form:
 *  (enc-val
 *	(<algo>
 *	   (<param_name1> <mpi>)
 *	    ...
 *         (<param_namen> <mpi>)
 *	))
 *
 * Note the <algo> must be given as a stringified OID or the special
 * string "rsa" */
KsbaError
ksba_cms_set_enc_val (KsbaCMS cms, int idx, KsbaConstSexp encval)
{
  /*FIXME: This shares most code with ...set_sig_val */
  const char *s, *endp;
  unsigned long n;

  if (!cms)
    return KSBA_Invalid_Value;
  if (idx)
    return KSBA_Invalid_Index; /* only one signer for now */

  s = encval;
  if (*s != '(')
    return KSBA_Invalid_Sexp;
  s++;

  n = strtoul (s, (char**)&endp, 10);
  s = endp;
  if (!n || *s!=':')
    return KSBA_Invalid_Sexp; /* we don't allow empty lengths */
  s++;
  if (n != 7 || memcmp (s, "enc-val", 7))
    return KSBA_Unknown_Sexp;
  s += 7;
  if (*s != '(')
    return digitp (s)? KSBA_Unknown_Sexp : KSBA_Invalid_Sexp;
  s++;

  /* break out the algorithm ID */
  n = strtoul (s, (char**)&endp, 10);
  s = endp;
  if (!n || *s != ':')
    return KSBA_Invalid_Sexp; /* we don't allow empty lengths */
  s++;
  xfree (cms->enc_val.algo);
  if (n==3 && s[0] == 'r' && s[1] == 's' && s[2] == 'a')
    { /* kludge to allow "rsa" to be passed as algorithm name */
      cms->enc_val.algo = xtrystrdup ("1.2.840.113549.1.1.1");
      if (!cms->enc_val.algo)
        return KSBA_Out_Of_Core;
    }
  else
    {
      cms->enc_val.algo = xtrymalloc (n+1);
      if (!cms->enc_val.algo)
        return KSBA_Out_Of_Core;
      memcpy (cms->enc_val.algo, s, n);
      cms->enc_val.algo[n] = 0;
    }
  s += n;

  /* And now the values - FIXME: For now we only support one */
  /* fixme: start loop */
  if (*s != '(')
    return digitp (s)? KSBA_Unknown_Sexp : KSBA_Invalid_Sexp;
  s++;
  n = strtoul (s, (char**)&endp, 10);
  s = endp;
  if (!n || *s != ':')
    return KSBA_Invalid_Sexp; 
  s++;
  s += n; /* ignore the name of the parameter */
  
  if (!digitp(s))
    return KSBA_Unknown_Sexp; /* but may also be an invalid one */
  n = strtoul (s, (char**)&endp, 10);
  s = endp;
  if (!n || *s != ':')
    return KSBA_Invalid_Sexp; 
  s++;
  xfree (cms->enc_val.value);
  cms->enc_val.value = xtrymalloc (n);
  if (!cms->enc_val.value)
    return KSBA_Out_Of_Core;
  memcpy (cms->enc_val.value, s, n);
  cms->enc_val.valuelen = n;
  s += n;
  if ( *s != ')')
    return KSBA_Unknown_Sexp; /* but may also be an invalid one */
  s++;
  /* fixme: end loop over parameters */

  /* we need 2 closing parenthesis */
  if ( *s != ')' || s[1] != ')')
    return KSBA_Invalid_Sexp; 

  return 0;
}




/**
 * ksba_cms_add_recipient:
 * @cms: A CMS object
 * @cert: A certificate used to describe the recipient.
 * 
 * This functions starts assembly of a new enevloped data content or adds
 * another recipient to the list of recipients.
 *
 * Note: after successful completion of this function ownership of
 * @cert is transferred to @cms.  
 * 
 * Return value: 0 on success or an error code.
 **/
KsbaError
ksba_cms_add_recipient (KsbaCMS cms, KsbaCert cert)
{
  /* for now we use the same structure */
  return ksba_cms_add_signer (cms, cert);
}




/*
   Content handler for parsing messages
*/

static KsbaError 
ct_parse_data (KsbaCMS cms)
{
  return KSBA_Not_Implemented;
}


static KsbaError 
ct_parse_signed_data (KsbaCMS cms)
{
  enum { 
    sSTART,
    sGOT_HASH,
    sIN_DATA,
    sERROR
  } state = sERROR;
  KsbaStopReason stop_reason = cms->stop_reason;
  KsbaError err = 0;

  cms->stop_reason = KSBA_SR_RUNNING;

  /* Calculate state from last reason and do some checks */
  if (stop_reason == KSBA_SR_GOT_CONTENT)
    {
      state = sSTART;
    }
  else if (stop_reason == KSBA_SR_NEED_HASH)
    {
      state = sGOT_HASH;
    }
  else if (stop_reason == KSBA_SR_BEGIN_DATA)
    {
      if (!cms->hash_fnc)
        err = KSBA_Missing_Action;
      else
        state = sIN_DATA;
    }
  else if (stop_reason == KSBA_SR_END_DATA)
    {
      state = sGOT_HASH;
    }
  else if (stop_reason == KSBA_SR_RUNNING)
    err = KSBA_Invalid_State;
  else if (stop_reason)
    err = KSBA_Bug;
  
  if (err)
    return err;

  /* Do the action */
  if (state == sSTART)
    err = _ksba_cms_parse_signed_data_part_1 (cms);
  else if (state == sGOT_HASH)
    err = _ksba_cms_parse_signed_data_part_2 (cms);
  else if (state == sIN_DATA)
    err = read_and_hash_cont (cms);
  else
    err = KSBA_Invalid_State;

  if (err)
    return err;

  /* Calculate new stop reason */
  if (state == sSTART)
    {
      if (cms->detached_data && !cms->data.digest)
        { /* We use this stop reason to inform the caller about a
             detached signatures.  Actually there is no need for him
             to hash the data now, he can do this also later. */
          stop_reason = KSBA_SR_NEED_HASH;
        }
      else 
        { /* The user must now provide a hash function so that we can 
             hash the data in the next round */
          stop_reason = KSBA_SR_BEGIN_DATA;
        }
    }
  else if (state == sIN_DATA)
    stop_reason = KSBA_SR_END_DATA;
  else if (state ==sGOT_HASH)
    stop_reason = KSBA_SR_READY;
    
  cms->stop_reason = stop_reason;
  return 0;
}


static KsbaError 
ct_parse_enveloped_data (KsbaCMS cms)
{
  enum { 
    sSTART,
    sREST,
    sINDATA,
    sERROR
  } state = sERROR;
  KsbaStopReason stop_reason = cms->stop_reason;
  KsbaError err = 0;

  cms->stop_reason = KSBA_SR_RUNNING;

  /* Calculate state from last reason and do some checks */
  if (stop_reason == KSBA_SR_GOT_CONTENT)
    {
      state = sSTART;
    }
  else if (stop_reason == KSBA_SR_DETACHED_DATA)
    {
      state = sREST;
    }
  else if (stop_reason == KSBA_SR_BEGIN_DATA)
    {
      state = sINDATA;
    }
  else if (stop_reason == KSBA_SR_END_DATA)
    {
      state = sREST;
    }
  else if (stop_reason == KSBA_SR_RUNNING)
    err = KSBA_Invalid_State;
  else if (stop_reason)
    err = KSBA_Bug;
  
  if (err)
    return err;

  /* Do the action */
  if (state == sSTART)
    err = _ksba_cms_parse_enveloped_data_part_1 (cms);
  else if (state == sREST)
    err = _ksba_cms_parse_enveloped_data_part_2 (cms);
  else if (state == sINDATA)
    err = read_encrypted_cont (cms);
  else
    err = KSBA_Invalid_State;

  if (err)
    return err;

  /* Calculate new stop reason */
  if (state == sSTART)
    {
      stop_reason = cms->detached_data? KSBA_SR_DETACHED_DATA
                                      : KSBA_SR_BEGIN_DATA;
    }
  else if (state == sINDATA)
    stop_reason = KSBA_SR_END_DATA;
  else if (state ==sREST)
    stop_reason = KSBA_SR_READY;
    
  cms->stop_reason = stop_reason;
  return 0;
}


static KsbaError 
ct_parse_digested_data (KsbaCMS cms)
{
  return KSBA_Not_Implemented;
}


static KsbaError 
ct_parse_encrypted_data (KsbaCMS cms)
{
  return KSBA_Not_Implemented;
}



/*
   Content handlers for building messages
*/

static KsbaError 
ct_build_data (KsbaCMS cms)
{
  return KSBA_Not_Implemented;
}



/* write everything up to the encapsulated data content type */
static KsbaError
build_signed_data_header (KsbaCMS cms)
{
  KsbaError err;
  char *buf;
  const char *s;
  size_t len;
  int i;

  /* Write the outer contentInfo */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;
  err = ksba_oid_from_str (cms->content.oid, &buf, &len);
  if (err)
    return err;
  err = _ksba_ber_write_tl (cms->writer,
                            TYPE_OBJECT_ID, CLASS_UNIVERSAL, 0, len);
  if (!err)
    err = ksba_writer_write (cms->writer, buf, len);
  xfree (buf);
  if (err)
    return err;
  
  err = _ksba_ber_write_tl (cms->writer, 0, CLASS_CONTEXT, 1, 0);
  if (err)
    return err;
  
  /* The SEQUENCE */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;

  /* figure out the CMSVersion to be used */
  if (0 /* fixme: have_attribute_certificates 
           || encapsulated_content != data
           || any_signer_info_is_version_3*/ )
    s = "\x03";
  else
    s = "\x01";
  err = _ksba_ber_write_tl (cms->writer, TYPE_INTEGER, CLASS_UNIVERSAL, 0, 1);
  if (err)
    return err;
  err = ksba_writer_write (cms->writer, s, 1);
  if (err)
    return err;
  
  /* SET OF DigestAlgorithmIdentifier */
  /* FIXME: We write a set with one element and assume a length of 11 !!*/
  err = _ksba_ber_write_tl (cms->writer, TYPE_SET, CLASS_UNIVERSAL, 1, 11);
  if (err)
    return err;
  for (i=0; (s = ksba_cms_get_digest_algo_list (cms, i)); i++)
    {
      err = _ksba_der_write_algorithm_identifier (cms->writer, s, NULL, 0);
      if (err)
        return err;
    }

  /* Write the (inner) encapsulatedContentInfo */
  /* if we have a detached signature we don't need to use undefinite
     length here - but it doesn't matter either */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;
  err = ksba_oid_from_str (cms->inner_cont_oid, &buf, &len);
  if (err)
    return err;
  err = _ksba_ber_write_tl (cms->writer,
                            TYPE_OBJECT_ID, CLASS_UNIVERSAL, 0, len);
  if (!err)
    err = ksba_writer_write (cms->writer, buf, len);
  xfree (buf);
  if (err)
    return err;

  if ( !cms->detached_data)
    { /* write the tag */
      err = _ksba_ber_write_tl (cms->writer, 0, CLASS_CONTEXT, 1, 0);
      if (err)
        return err;
    }

  return err;
}

/* Set the issuer/serial from the cert to the node.
   mode 0: sid 
   mode 1: rid
 */
static KsbaError
set_issuer_serial (AsnNode info, KsbaCert cert, int mode)
{
  KsbaError err;
  AsnNode dst, src;

  if (!info || !cert)
    return KSBA_Invalid_Value;

  src = _ksba_asn_find_node (cert->root,
                             "Certificate.tbsCertificate.serialNumber");
  dst = _ksba_asn_find_node (info,
                             mode?
                             "rid.issuerAndSerialNumber.serialNumber":
                             "sid.issuerAndSerialNumber.serialNumber");
  err = _ksba_der_copy_tree (dst, src, cert->image);
  if (err)
    return err;

  src = _ksba_asn_find_node (cert->root,
                             "Certificate.tbsCertificate.issuer");
  dst = _ksba_asn_find_node (info,
                             mode?
                             "rid.issuerAndSerialNumber.issuer":
                             "sid.issuerAndSerialNumber.issuer");
  err = _ksba_der_copy_tree (dst, src, cert->image);
  if (err)
    return err;

  return 0;
}


/* Write the END of data NULL tag and everything we can write before
   the user can calculate the signature */
static KsbaError
build_signed_data_attributes (KsbaCMS cms) 
{
  KsbaError err;
  int signer;
  KsbaAsnTree cms_tree;
  struct certlist_s *certlist;
  struct oidlist_s *digestlist;

  /* Write the End tag */
  err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
  if (err)
    return err;

  /* FIXME: Write optional certificates */

  /* FIXME: Write the optional CRLs */


  /* Now we have to prepare the signer info.  For now we will just build the
     signedAttributes, so that the suer can do the signature calculation */
  err = ksba_asn_create_tree ("cms", &cms_tree);
  if (err)
    return err;
  /* fixme: we must release root and cms_tree on error */

  certlist = cms->cert_list;
  if (!certlist)
    return KSBA_Missing_Value; /* oops */
  digestlist = cms->digest_algos;
  if (!digestlist)
    return KSBA_Missing_Value; /* oops */

  for (signer=0; certlist;
       signer++, certlist = certlist->next, digestlist = digestlist->next)
    {
      AsnNode attr, root;
      AsnNode n;
      unsigned char *image;
      int i;
      struct {
        AsnNode root;
        unsigned char *image;
      } attrarray[2]; 
      int attridx = 0;

      if (!digestlist)
        return KSBA_Missing_Value; /* oops */

      if (!certlist->cert || !digestlist->oid)
        return KSBA_Bug;

      /* the message digest is pretty important */
      attr = _ksba_asn_expand_tree (cms_tree->parse_tree, 
                                    "CryptographicMessageSyntax.Attribute");
      if (!attr)
        return KSBA_Element_Not_Found;
      n = _ksba_asn_find_node (attr, "Attribute.attrType");
      if (!n)
        return KSBA_Element_Not_Found;
      err = _ksba_der_store_oid (n, oidstr_messageDigest);
      if (err)
        return err;
      n = _ksba_asn_find_node (attr, "Attribute.attrValues");
      if (!n || !n->down)
        return KSBA_Element_Not_Found;
      n = n->down; /* fixme: ugly hack */
      assert (certlist && certlist->msg_digest_len);
      err = _ksba_der_store_octet_string (n, certlist->msg_digest,
                                          certlist->msg_digest_len);
      if (err)
        return err;
      err = _ksba_der_encode_tree (attr, &image, NULL);
      if (err)
          return err;
      attrarray[attridx].root = attr;
      attrarray[attridx].image = image;
      attridx++;

      /* insert the signing time */
      if (certlist->signing_time)
        {
          attr = _ksba_asn_expand_tree (cms_tree->parse_tree, 
                                  "CryptographicMessageSyntax.Attribute");
          if (!attr)
            return KSBA_Element_Not_Found;
          n = _ksba_asn_find_node (attr, "Attribute.attrType");
          if (!n)
            return KSBA_Element_Not_Found;
          err = _ksba_der_store_oid (n, oidstr_signingTime);
          if (err)
            return err;
          n = _ksba_asn_find_node (attr, "Attribute.attrValues");
          if (!n || !n->down)
            return KSBA_Element_Not_Found;
          n = n->down; /* fixme: ugly hack */
          err = _ksba_der_store_time (n, certlist->signing_time);
          if (err)
            return err;
          err = _ksba_der_encode_tree (attr, &image, NULL);
          if (err)
            return err;
          /* we will use the attributes again - so save them */
          attrarray[attridx].root = attr;
          attrarray[attridx].image = image;
          attridx++;
        }

      /* now copy them to an SignerInfos tree.  This tree is not
         complete but suitable for ksba_cms_hash_igned_attributes() */
      root = _ksba_asn_expand_tree (cms_tree->parse_tree,  
                                    "CryptographicMessageSyntax.SignerInfos"); 
      n = _ksba_asn_find_node (root, "SignerInfos..signedAttrs");
      if (!n || !n->down) 
        return KSBA_Element_Not_Found; 
      /* This is another ugly hack to move to the element we want */
      for (n = n->down->down; n && n->type != TYPE_SEQUENCE; n = n->right)
        ;
      if (!n) 
        return KSBA_Element_Not_Found; 



      for (i=0; i < attridx; i++)
        {
          if (i && !_ksba_asn_insert_copy (n))
            return KSBA_Out_Of_Core;
          err = _ksba_der_copy_tree (n, attrarray[i].root, attrarray[i].image);
          if (err)
            return err;
          /* fixme: release this array slot */
        }

      err = _ksba_der_encode_tree (root, &image, NULL);
      if (err)
          return err;

      /* fixme: the signer_info structure can only save one signerinfo */
      _ksba_asn_release_nodes (cms->signer_info.root);
      xfree (cms->signer_info.image);
      cms->signer_info.root = root;
      cms->signer_info.image = image;
    }

  return 0;
}




/* The user has calculated the signatures and we can therefore write
   everything left over to do. */
static KsbaError 
build_signed_data_rest (KsbaCMS cms) 
{
  KsbaError err;
  int signer;
  KsbaAsnTree cms_tree;
  struct certlist_s *certlist;
  struct oidlist_s *digestlist;

  /* Now we can really write the signer info */
  err = ksba_asn_create_tree ("cms", &cms_tree);
  if (err)
    return err;
  /* fixme: we must release root and cms_tree on error */

  certlist = cms->cert_list;
  if (!certlist)
    return KSBA_Missing_Value; /* oops */
  digestlist = cms->digest_algos;
  if (!digestlist)
    return KSBA_Missing_Value; /* oops */

  for (signer=0; certlist;
       signer++, certlist = certlist->next, digestlist = digestlist->next)
    {
      AsnNode root, n, n2;
      unsigned char *image;
      size_t imagelen;

      if (!digestlist)
        return KSBA_Missing_Value; /* oops */
      if (!certlist->cert || !digestlist->oid)
        return KSBA_Bug;

      root = _ksba_asn_expand_tree (cms_tree->parse_tree, 
                                    "CryptographicMessageSyntax.SignerInfos");

      /* We store a version of 1 because we use the issuerAndSerialNumber */
      n = _ksba_asn_find_node (root, "SignerInfos..version");
      if (!n)
        return KSBA_Element_Not_Found;
      err = _ksba_der_store_integer (n, "\x00\x00\x00\x01\x01");
      if (err)
        return err;

      /* Store the sid */
      n = _ksba_asn_find_node (root, "SignerInfos..sid");
      if (!n)
        return KSBA_Element_Not_Found;

      err = set_issuer_serial (n, certlist->cert, 0);
      if (err)
        return err;

      /* store the digestAlgorithm */
      n = _ksba_asn_find_node (root, "SignerInfos..digestAlgorithm.algorithm");
      if (!n)
        return KSBA_Element_Not_Found;
      err = _ksba_der_store_oid (n, digestlist->oid);
      if (err)
        return err;
      n = _ksba_asn_find_node (root, "SignerInfos..digestAlgorithm.parameters");
      if (!n)
        return KSBA_Element_Not_Found;
      err = _ksba_der_store_null (n);
      if (err)
        return err;

      /* and the signed attributes */
      n = _ksba_asn_find_node (root, "SignerInfos..signedAttrs");
      if (!n || !n->down) 
        return KSBA_Element_Not_Found; 
      assert (cms->signer_info.root);
      assert (cms->signer_info.image);
      n2 = _ksba_asn_find_node (cms->signer_info.root,
                                "SignerInfos..signedAttrs");
      if (!n2 || !n->down) 
        return KSBA_Element_Not_Found; 
      err = _ksba_der_copy_tree (n, n2, cms->signer_info.image);
      if (err)
        return err;
      image = NULL;

      /* store the signatureAlgorithm */
      if (!cms->sig_val.algo || !cms->sig_val.value)
        return KSBA_Missing_Value;
      n = _ksba_asn_find_node (root, "SignerInfos..signatureAlgorithm.algorithm");
      if (!n)
        return KSBA_Element_Not_Found;
      err = _ksba_der_store_oid (n, cms->sig_val.algo);
      if (err)
        return err;
      n = _ksba_asn_find_node (root, "SignerInfos..signatureAlgorithm.parameters");
      if (!n)
        return KSBA_Element_Not_Found;
      err = _ksba_der_store_null (n);
      if (err)
        return err;

      /* store the signature  */
      if (!cms->sig_val.value)
        return KSBA_Missing_Value;
      n = _ksba_asn_find_node (root, "SignerInfos..signature");
      if (!n)
        return KSBA_Element_Not_Found;
      err = _ksba_der_store_octet_string (n, cms->sig_val.value,
                                          cms->sig_val.valuelen);
      if (err)
        return err;


      /* Make the DER encoding and write it out */
      err = _ksba_der_encode_tree (root, &image, &imagelen);
      if (err)
          return err;

      err = ksba_writer_write (cms->writer, image, imagelen);
      if (err )
        return err;
      /* fixme: release what we don't need */
    }

#if 0
  /* HACK for testing */
  err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
  if (err)
    return err;
  err = _ksba_ber_write_tl (cms->writer, 0, 0, 0, 0);
  if (err)
    return err;
#endif

  return 0;
}




static KsbaError 
ct_build_signed_data (KsbaCMS cms)
{
  enum { 
    sSTART,
    sDATAREADY,
    sGOTSIG,
    sERROR
  } state = sERROR;
  KsbaStopReason stop_reason;
  KsbaError err = 0;

  stop_reason = cms->stop_reason;
  cms->stop_reason = KSBA_SR_RUNNING;

  /* Calculate state from last reason and do some checks */
  if (stop_reason == KSBA_SR_GOT_CONTENT)
    {
      state = sSTART;
    }
  else if (stop_reason == KSBA_SR_BEGIN_DATA)
    {
      /* fixme: check that the message digest has been set */
      state = sDATAREADY;
    }
  else if (stop_reason == KSBA_SR_END_DATA)
    state = sDATAREADY;
  else if (stop_reason == KSBA_SR_NEED_SIG)
    {
      if (!cms->sig_val.algo)
        err = KSBA_Missing_Action; /* No ksba_cms_set_sig_val () called */
      state = sGOTSIG;
    }
  else if (stop_reason == KSBA_SR_RUNNING)
    err = KSBA_Invalid_State;
  else if (stop_reason)
    err = KSBA_Bug;
  
  if (err)
    return err;

  /* Do the action */
  if (state == sSTART)
    {
      /* figure out whether a detached signature is requested */
      if (cms->cert_list && cms->cert_list->msg_digest_len)
        cms->detached_data = 1;
      else
        cms->detached_data = 0;
      /* and start encoding */
      err = build_signed_data_header (cms);
    }
  else if (state == sDATAREADY)
    err = build_signed_data_attributes (cms);
  else if (state == sGOTSIG)
    err = build_signed_data_rest (cms);
  else
    err = KSBA_Invalid_State;

  if (err)
    return err;

  /* Calculate new stop reason */
  if (state == sSTART)
    {
      /* user should write the data and calculate the hash or do
         nothing in case of END_DATA */
      stop_reason = cms->detached_data? KSBA_SR_END_DATA
                                      : KSBA_SR_BEGIN_DATA;
    }
  else if (state == sDATAREADY)
    stop_reason = KSBA_SR_NEED_SIG;
  else if (state == sGOTSIG)
    stop_reason = KSBA_SR_READY;
    
  cms->stop_reason = stop_reason;
  return 0;
}


/* write everything up to the encryptedContentInfo including the tag */
static KsbaError
build_enveloped_data_header (KsbaCMS cms)
{
  KsbaError err;
  int recpno;
  KsbaAsnTree cms_tree;
  struct certlist_s *certlist;
  char *buf;
  const char *s;
  size_t len;

  /* Write the outer contentInfo */
  /* fixme: code is shared with signed_data_header */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;
  err = ksba_oid_from_str (cms->content.oid, &buf, &len);
  if (err)
    return err;
  err = _ksba_ber_write_tl (cms->writer,
                            TYPE_OBJECT_ID, CLASS_UNIVERSAL, 0, len);
  if (!err)
    err = ksba_writer_write (cms->writer, buf, len);
  xfree (buf);
  if (err)
    return err;
  
  err = _ksba_ber_write_tl (cms->writer, 0, CLASS_CONTEXT, 1, 0);
  if (err)
    return err;
  
  /* The SEQUENCE */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;

  /* figure out the CMSVersion to be used (from rfc2630):
     version is the syntax version number.  If originatorInfo is
     present, then version shall be 2.  If any of the RecipientInfo
     structures included have a version other than 0, then the version
     shall be 2.  If unprotectedAttrs is present, then version shall
     be 2.  If originatorInfo is absent, all of the RecipientInfo
     structures are version 0, and unprotectedAttrs is absent, then
     version shall be 0. 
     
     For SPHINX the version number must be 0.
  */
  s = "\x00"; 
  err = _ksba_ber_write_tl (cms->writer, TYPE_INTEGER, CLASS_UNIVERSAL, 0, 1);
  if (err)
    return err;
  err = ksba_writer_write (cms->writer, s, 1);
  if (err)
    return err;

  /* Note: originatorInfo is not yet implemented and must not be used
     for SPHINX */

  /* Now we write the recipientInfo */
  err = ksba_asn_create_tree ("cms", &cms_tree);
  if (err)
    return err;
  /* fixme: we must cms_tree on error */

  certlist = cms->cert_list;
  if (!certlist)
    return KSBA_Missing_Value; /* oops */

  for (recpno=0; certlist; recpno++, certlist = certlist->next)
    {
      AsnNode root, n;
      unsigned char *image;
      size_t imagelen;

      if (!certlist->cert)
        return KSBA_Bug;

      root = _ksba_asn_expand_tree (cms_tree->parse_tree, 
                                "CryptographicMessageSyntax.RecipientInfos");

      /* We store a version of 0 because we are only allowed to use
         the issuerAndSerialNumber for SPHINX */
      n = _ksba_asn_find_node (root, "RecipientInfos..ktri.version");
      if (!n)
        return KSBA_Element_Not_Found;
      err = _ksba_der_store_integer (n, "\x00\x00\x00\x01\x00");
      if (err)
        return err;

      /* Store the rid */
      n = _ksba_asn_find_node (root, "RecipientInfos..ktri.rid");
      if (!n)
        return KSBA_Element_Not_Found;

      err = set_issuer_serial (n, certlist->cert, 1);
      if (err)
        return err;

      /* store the keyEncryptionAlgorithm */
      if (!cms->enc_val.algo || !cms->enc_val.value)
        return KSBA_Missing_Value;
      n = _ksba_asn_find_node (root, 
                  "RecipientInfos..ktri.keyEncryptionAlgorithm.algorithm");
      if (!n)
        return KSBA_Element_Not_Found;
      err = _ksba_der_store_oid (n, cms->enc_val.algo);
      if (err)
        return err;
      n = _ksba_asn_find_node (root, 
                  "RecipientInfos..ktri.keyEncryptionAlgorithm.parameters");
      if (!n)
        return KSBA_Element_Not_Found;
      err = _ksba_der_store_null (n); 
      if (err)
        return err;

      /* store the encryptedKey  */
      if (!cms->enc_val.value)
        return KSBA_Missing_Value;
      n = _ksba_asn_find_node (root, "RecipientInfos..ktri.encryptedKey");
      if (!n)
        return KSBA_Element_Not_Found;
      err = _ksba_der_store_octet_string (n,
                                          cms->enc_val.value,
                                          cms->enc_val.valuelen);
      if (err)
        return err;


      /* Make the DER encoding and write it out */
      err = _ksba_der_encode_tree (root, &image, &imagelen);
      if (err)
          return err;

      err = ksba_writer_write (cms->writer, image, imagelen);
      if (err )
        return err;
      /* fixme: release what we don't need */
    }

  
  /* Write the (inner) encryptedContentInfo */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;
  err = ksba_oid_from_str (cms->inner_cont_oid, &buf, &len);
  if (err)
    return err;
  err = _ksba_ber_write_tl (cms->writer,
                            TYPE_OBJECT_ID, CLASS_UNIVERSAL, 0, len);
  if (!err)
    err = ksba_writer_write (cms->writer, buf, len);
  xfree (buf);
  if (err)
    return err;

  /* and the encryptionAlgorithm */
  err = _ksba_der_write_algorithm_identifier (cms->writer, 
                                              cms->encr_algo_oid,
                                              cms->encr_iv,
                                              cms->encr_ivlen);
  if (err)
    return err;

  /* write the tag for the encrypted data, it is an implicit octect
     string in constructed form and indefinite length */
  err = _ksba_ber_write_tl (cms->writer, 0, CLASS_CONTEXT, 1, 0);
  if (err)
    return err;

  /* Now the encrypted data should be written */

  return 0;
}


static KsbaError 
ct_build_enveloped_data (KsbaCMS cms)
{
  enum { 
    sSTART,
    sINDATA,
    sREST,
    sERROR
  } state = sERROR;
  KsbaStopReason stop_reason;
  KsbaError err = 0;

  stop_reason = cms->stop_reason;
  cms->stop_reason = KSBA_SR_RUNNING;

  /* Calculate state from last reason and do some checks */
  if (stop_reason == KSBA_SR_GOT_CONTENT)
    state = sSTART;
  else if (stop_reason == KSBA_SR_BEGIN_DATA)
    state = sINDATA;
  else if (stop_reason == KSBA_SR_END_DATA)
    state = sREST;
  else if (stop_reason == KSBA_SR_RUNNING)
    err = KSBA_Invalid_State;
  else if (stop_reason)
    err = KSBA_Bug;
  
  if (err)
    return err;

  /* Do the action */
  if (state == sSTART)
    err = build_enveloped_data_header (cms);
  else if (state == sINDATA)
    err = write_encrypted_cont (cms);
  else if (state == sREST)
    err = 0; /* SPHINX does no allow for unprotectedAttributes */
  else
    err = KSBA_Invalid_State;

  if (err)
    return err;

  /* Calculate new stop reason */
  if (state == sSTART)
    { /* user should now write the encrypted data */
      stop_reason = KSBA_SR_BEGIN_DATA;
    }
  else if (state == sINDATA)
    { /* tell the user that we wrote everything */
      stop_reason = KSBA_SR_END_DATA;
    }
  else if (state == sREST)
    {
      stop_reason = KSBA_SR_READY;
    }

  cms->stop_reason = stop_reason;
  return 0;
}


static KsbaError 
ct_build_digested_data (KsbaCMS cms)
{
  return KSBA_Not_Implemented;
}


static KsbaError 
ct_build_encrypted_data (KsbaCMS cms)
{
  return KSBA_Not_Implemented;
}


