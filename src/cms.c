/* cms.c - cryptographic message syntax main functions
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

static KsbaError ct_parse_signed_data (KsbaCMS cms);
static KsbaError ct_parse_enveloped_data (KsbaCMS cms);
static KsbaError ct_parse_digested_data (KsbaCMS cms);
static KsbaError ct_parse_encrypted_data (KsbaCMS cms);
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
  {  "1.2.840.113549.1.7.1", KSBA_CT_DATA             },
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

/* 1.2.840.113549.1.9.4 */
static char oid_messageDigest[9] = "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x04";


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
  xfree (cms->encap_cont_type);
  xfree (cms->data.digest);
  _ksba_asn_release_nodes (cms->signer_info.root);
  xfree (cms->signer_info.image);
  xfree (cms->signer_info.cache.digest_algo);
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
      if (!cms->encap_cont_type)
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

  if (what == 1 && cms->encap_cont_type)
    {
      for (i=0; content_handlers[i].oid; i++)
        {
          if (!strcmp (content_handlers[i].oid, cms->encap_cont_type))
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
    return cms->encap_cont_type;
  return NULL;
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


KsbaError
ksba_cms_get_issuer_serial (KsbaCMS cms, int idx,
                            char **r_issuer, unsigned char **r_serial)
{
  KsbaError err;
  AsnNode n;

  if (!cms)
    return KSBA_Invalid_Value;
  if (!cms->signer_info.root)
    return KSBA_No_Data;
  
  if (r_issuer)
    {
      n = _ksba_asn_find_node (cms->signer_info.root,
                               "SignerInfos..sid.issuerAndSerialNumber.issuer");
      if (!n || !n->down)
        return KSBA_No_Value; 
      n = n->down; /* dereference the choice node */
      
      if (n->off == -1)
        {
          fputs ("get_issuer problem at node:\n", stderr);
          _ksba_asn_node_dump_all (n, stderr);
          return KSBA_General_Error;
        }
      err = _ksba_dn_to_str (cms->signer_info.image, n, r_issuer);
      if (err)
        return err;
    }

  if (r_serial)
    {
      unsigned char *p;

      /* fixme: we do not release the r_issuer stuff on error */
      n = _ksba_asn_find_node (cms->signer_info.root,
                      "SignerInfos..sid.issuerAndSerialNumber.serialNumber");
      if (!n)
        return KSBA_No_Value; 
      
      if (n->off == -1)
        {
          fputs ("get_serial problem at node:\n", stderr);
          _ksba_asn_node_dump_all (n, stderr);
          return KSBA_General_Error;
        }

      p = xtrymalloc (n->len + 4);
      if (!p)
        return KSBA_Out_Of_Core;

      p[0] = n->len >> 24;
      p[1] = n->len >> 16;
      p[2] = n->len >> 8;
      p[3] = n->len;
      memcpy (p+4, cms->signer_info.image + n->off + n->nhdr, n->len);
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
 * its OID This is the algorithm acually used to calculate the
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
 * loop to get all certificates.  NOte: This function can be used only
 * once because an already retrieved cert is deleted from the CMS
 * object for efficiency. FIXME: we should use reference counting instead.
 * 
 * Return value: A Certificate object or NULL for end of list or error
 **/
KsbaCert
ksba_cms_get_cert (KsbaCMS cms, int idx)
{
  struct certlist_s *cl;
  KsbaCert cert;

  if (!cms || idx < 0)
    return NULL;

  for (cl=cms->cert_list; cl && idx; cl = cl->next, idx--)
    ;
  if (!cl)
    return NULL;
  cert = cl->cert;
  cl->cert = NULL;
  return cert;
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
    return 0; /* this is okay, because the element is optional */

  n = _ksba_asn_find_type_value (cms->signer_info.image, nsiginfo, 0,
                                 oid_messageDigest, DIM(oid_messageDigest));
  if (!n)
    return KSBA_Value_Not_Found; /* message digest is required */

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
char *
ksba_cms_get_sig_val (KsbaCMS cms, int idx)
{
  AsnNode n, n2;
  KsbaError err;
  char *string;

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
      cms->encap_cont_type = oid;
    }

  return 0;
}


/**
 * ksba_cms_add_digest_algo:
 * @cms:  A CMS object 
 * @oid: A stringified object OID describing the hash algorithm
 * 
 * Set the algorithm to be used for crerating the hash. Note, that we
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
 * @cert is transferred to @cms.  The caller should not continue to
 * use cert.  Fixme:  We  should use reference counting instead.
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

  cl->cert = cert;
  cl->next = cms->cert_list;
  cms->cert_list = cl;
  return 0;
}


/* Add the issuer/serial from the cert to the sid list */
static KsbaError
add_issuer_serial (KsbaCMS cms, KsbaCert cert)
{
  KsbaError err;
  AsnNode dst, src;

  if (!cms)
    return KSBA_Invalid_Value;
  if (!cms->signer_info.root)
    return KSBA_Conflict;

  src = _ksba_asn_find_node (cert->root,
                             "Certificate.tbsCertificate.serialNumber");
  dst = _ksba_asn_find_node (cms->signer_info.root,
                      "SignerInfos..sid.issuerAndSerialNumber.serialNumber");
  err = _ksba_der_copy_tree (dst, src, cert->image);
  if (err)
    return err;

  src = _ksba_asn_find_node (cert->root,
                             "Certificate.tbsCertificate.issuer");
  dst = _ksba_asn_find_node (cms->signer_info.root,
                      "SignerInfos..sid.issuerAndSerialNumber.issuer");
  err = _ksba_der_copy_tree (dst, src, cert->image);
  if (err)
    return err;


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






/*
   Content handler for parsing messages
*/

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
    ; /* start a parser part which does the hash job */
  else
    err = KSBA_Invalid_State;

  if (err)
    return err;

  /* Calculate new stop reason */
  if (state == sSTART)
    {
      if (cms->detached_signature && !cms->data.digest)
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
  return KSBA_Not_Implemented;
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
  

  /* figure out the CMSVersion to be used */
  if (1 /* fixme: have_attribute_certificates 
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
  for (i=0; (s = ksba_cms_get_digest_algo_list (cms, i)); i++)
    {
      err = _ksba_der_write_algorithm_identifier (cms->writer, s);
      if (err)
        return err;
    }

  /* Write the (inner) encapsulatedContentInfo */
  err = _ksba_ber_write_tl (cms->writer, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1, 0);
  if (err)
    return err;
  err = ksba_oid_from_str (cms->encap_cont_type, &buf, &len);
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
  
  return err;
}

/* Write the END of data NULL tag and everything we can write before
   the user can calculate the signature */
static KsbaError
build_signed_data_attributes (KsbaCMS cms) 
{
  KsbaError err;


  /* The NULL tag to end the data */
  err = _ksba_ber_write_tl (cms->writer, TYPE_NULL, CLASS_UNIVERSAL, 0, 0);
  if (err)
    return err;

  /* FIXME: Write optional certificates */

  /* FIXME: Write the optional CRLs */

  /* Now we have to prepare the signer info */




  return 0;
}


static KsbaError 
ct_build_signed_data (KsbaCMS cms)
{
  enum { 
    sSTART,
    sDATAREADY,
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
  else if (stop_reason == KSBA_SR_BEGIN_DATA)
    {
      /* fixme: check that the message digest has been set */
      state = sDATAREADY;
    }
  else if (stop_reason == KSBA_SR_RUNNING)
    err = KSBA_Invalid_State;
  else if (stop_reason)
    err = KSBA_Bug;
  
  if (err)
    return err;

  /* Do the action */
  if (state == sSTART)
    err = build_signed_data_header (cms);
  else if (state == sDATAREADY)
    err = build_signed_data_attributes (cms);
  else
    err = KSBA_Invalid_State;

  if (err)
    return err;

  /* Calculate new stop reason */
  if (state == sSTART)
    {
      /* user should write the data */
      stop_reason = KSBA_SR_BEGIN_DATA;
    }
  else if (state == sDATAREADY)
    stop_reason = KSBA_SR_NEED_SIG;
    
  cms->stop_reason = stop_reason;
  return 0;
}


static KsbaError 
ct_build_enveloped_data (KsbaCMS cms)
{
  return KSBA_Not_Implemented;
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


