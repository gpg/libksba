/* crl.c - CRL parser
 *      Copyright (C) 2002 g10 Code GmbH
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

#include "convert.h"
#include "keyinfo.h"
#include "der-encoder.h"
#include "ber-help.h"
#include "ber-decoder.h"
#include "crl.h"



/**
 * ksba_crl_new:
 * 
 * Create a new and empty CRL object
 * 
 * Return value: A CRL object or NULL in case of memory problems.
 **/
KsbaCRL
ksba_crl_new (void)
{
  KsbaCRL crl;

  crl = xtrycalloc (1, sizeof *crl);
  if (!crl)
    return NULL;


  return crl;
}

/**
 * ksba_crl_release:
 * @crl: A CRL object
 * 
 * Release a CRL object.
 **/
void
ksba_crl_release (KsbaCRL crl)
{
  if (!crl)
    return;
  xfree (crl->algo.oid);
  xfree (crl->algo.parm);
  
  _ksba_asn_release_nodes (crl->issuer.root);
  xfree (crl->issuer.image);

  xfree (crl->item.serial);

  xfree (crl->sig_val.algo);
  xfree (crl->sig_val.value);
  xfree (crl);
}


KsbaError
ksba_crl_set_reader (KsbaCRL crl, KsbaReader r)
{
  if (!crl || !r)
    return KSBA_Invalid_Value;
  
  crl->reader = r;
  return 0;
}


/* 
   access functions
*/


/**
 * ksba_crl_get_digest_algo:
 * @cms: CMS object
 * 
 * Figure out the the digest algorithm used for the signature and return
 * its OID.  
 *
 * Return value: NULL if the signature algorithm is not yet available
 * or there is a mismatched between "tbsCertList.signature" and
 * "signatureAlgorithm"; on success the OID is returned which is valid
 * as long as the CRL object is valid.
 **/
const char *
ksba_crl_get_digest_algo (KsbaCRL crl)
{
  if (!crl)
    return NULL;

  /* fixme: implement the described check */

  return crl->algo.oid;
}


/**
 * ksba_crl_get_issuer:
 * @cms: CMS object
 * @r_issuer: returns the issuer
 * 
 * This functions returns the issuer of the CRL.  The caller must
 * release the returned object.
 * 
 * Return value: 0 on success or an error code
 **/
KsbaError
ksba_crl_get_issuer (KsbaCRL crl, char **r_issuer)
{
  KsbaError err;
  AsnNode n;
  const unsigned char *image;

  if (!crl || !r_issuer)
    return KSBA_Invalid_Value;
  if (!crl->issuer.root)
    return KSBA_No_Data;

  n = crl->issuer.root;
  image = crl->issuer.image;
  
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

  return err;
}

/**
 * ksba_crl_get_update_times:
 * @crl: CRL object
 * @this: Returns the thisUpdate value
 * @next: Returns the nextUpdate value.
 * 
 * Return value: 0 on success or an error code
 **/
KsbaError
ksba_crl_get_update_times (KsbaCRL crl, time_t *this, time_t *next)
{
  if (!crl)
    return KSBA_Invalid_Value;
  if (crl->this_update == (time_t)(-1) || crl->next_update == (time_t)(-1))
    return KSBA_Invalid_Time;
  if (this)
    *this = crl->this_update;
  if (next)
    *next = crl->next_update;
  return 0;
}

/**
 * ksba_crl_get_item:
 * @crl: CRL object
 * @r_serial: Returns a S-exp with the serial number; caller must free.
 * @r_revocation_date: Returns the recocation date
 * @r_reason: Retrun the reason for revocation
 * 
 * Return the serial number, revocation time and reason of the current
 * item.  Any of these arguments may be passed as %NULL if the value
 * is not of interest.  This function should be used after the parse
 * function came back with %KSBA_SR_GOT_ITEM.  For efficiency reasons
 * the function shouild be called only once, the implementation may
 * return an error for the second call.
 * 
 * Return value: 0 in success or an error code.
 **/
KsbaError
ksba_crl_get_item (KsbaCRL crl, KsbaSexp *r_serial,
                   time_t *r_revocation_date, KsbaCRLReason *r_reason)
{ 
  if (!crl)
    return KSBA_Invalid_Value;

  if (r_serial)
    {
      if (!crl->item.serial)
        return KSBA_No_Data;
      *r_serial = crl->item.serial;
      crl->item.serial = NULL;
    }
  if (r_revocation_date)
    *r_revocation_date = crl->item.revocation_date;
  if (r_reason)
    *r_reason = crl->item.reason;
  return 0;
}



/**
 * ksba_crl_get_sig_val:
 * @crl: CRL object
 * 
 * Return the actual signature in a format suitable to be used as
 * input to Libgcrypt's verification function.  The caller must free
 * the returned string.
 * 
 * Return value: NULL or a string with an S-Exp.
 **/
KsbaSexp
ksba_crl_get_sig_val (KsbaCRL crl)
{
  AsnNode n, n2;
  KsbaError err;
  KsbaSexp string;


  string = NULL;
#if 0

  if (!crl)
    return NULL;
  if (!crl->issuersigner_info.root)
    return NULL;

  n = _ksba_asn_find_node (crl->signer_info.root,
                           "SignerInfos..signatureAlgorithm");
  if (!n)
      return NULL;
  if (n->off == -1)
      return NULL;

  n2 = n->right; /* point to the actual value */
  err = _ksba_sigval_to_sexp (crl->signer_info.image + n->off,
                              n->nhdr + n->len
                              + ((!n2||n2->off == -1)? 0:(n2->nhdr+n2->len)),
                              &string);
  if (err)
      return NULL;
#endif
  return string;
}



/*
  Parser functions 
*/

/* read one byte */
static int
read_byte (KsbaReader reader)
{
  unsigned char buf;
  size_t nread;
  int rc;

  do
    rc = ksba_reader_read (reader, &buf, 1, &nread);
  while (!rc && !nread);
  return rc? -1: buf;
}

/* read COUNT bytes into buffer.  Return 0 on success */
static int 
read_buffer (KsbaReader reader, char *buffer, size_t count)
{
  size_t nread;

  while (count)
    {
      if (ksba_reader_read (reader, buffer, count, &nread))
        return -1;
      buffer += nread;
      count -= nread;
    }
  return 0;
}

/* Create a new decoder and run it for the given element */
/* Fixme: this code is duplicated from cms-parser.c */
static KsbaError
create_and_run_decoder (KsbaReader reader, const char *elem_name,
                        AsnNode *r_root,
                        unsigned char **r_image, size_t *r_imagelen)
{
  KsbaError err;
  KsbaAsnTree crl_tree;
  BerDecoder decoder;

  err = ksba_asn_create_tree ("tmttv2", &crl_tree);
  if (err)
    return err;

  decoder = _ksba_ber_decoder_new ();
  if (!decoder)
    {
      ksba_asn_tree_release (crl_tree);
      return KSBA_Out_Of_Core;
    }

  err = _ksba_ber_decoder_set_reader (decoder, reader);
  if (err)
    {
      ksba_asn_tree_release (crl_tree);
      _ksba_ber_decoder_release (decoder);
      return err;
    }

  err = _ksba_ber_decoder_set_module (decoder, crl_tree);
  if (err)
    {
      ksba_asn_tree_release (crl_tree);
      _ksba_ber_decoder_release (decoder);
      return err;
    }
  
  err = _ksba_ber_decoder_decode (decoder, elem_name,
                                  r_root, r_image, r_imagelen);
  
  _ksba_ber_decoder_release (decoder);
  ksba_asn_tree_release (crl_tree);
  return err;
}



/* Parse the fixed block at the beginning.  We use a custom parser
   here becuase out BEr-decoder is not yet able to stop at certain
   points */
static KsbaError
parse_to_next_update (KsbaCRL crl)
{
  KsbaError err;
  struct tag_info ti;
  unsigned long outer_len, tbs_len;
  int outer_ndef, tbs_ndef;
  int c;
  unsigned char tmpbuf[500]; /* for OID or algorithmIdentifier */
  size_t nread;

  /* read the outer sequence */
  err = _ksba_ber_read_tl (crl->reader, &ti);
  if (err)
    return err;
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE
         && ti.is_constructed) )
    return KSBA_Invalid_CRL_Object;
  outer_len = ti.length; 
  outer_ndef = ti.ndef;
  if (!outer_ndef && outer_len < 10)
    return KSBA_Object_Too_Short; 

  /* read the tbs sequence */
  /* fixme: we need to keep a copy of those bytes for hashing */
  err = _ksba_ber_read_tl (crl->reader, &ti);
  if (err)
    return err;
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE
         && ti.is_constructed) )
    return KSBA_Invalid_CRL_Object;
  if (!outer_ndef)
    {
      if (outer_len < ti.nhdr)
        return KSBA_BER_Error; /* triplet header larger that outer sequence */
      outer_len -= ti.nhdr;
      if (!ti.ndef && outer_len < ti.length)
        return KSBA_BER_Error; /* triplet larger that outer sequence */
      outer_len -= ti.length;
    }
  tbs_len = ti.length; 
  tbs_ndef = ti.ndef;
  if (!tbs_ndef && tbs_len < 10)
    return KSBA_Object_Too_Short; 

  /* read the optional version integer */
  crl->crl_version = -1;
  err = _ksba_ber_read_tl (crl->reader, &ti);
  if (err)
    return err;
  if ( ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_INTEGER)
    {
      if ( ti.is_constructed || !ti.length )
        return KSBA_Invalid_CRL_Object; 
      if (!tbs_ndef)
        {
          if (tbs_len < ti.nhdr)
            return KSBA_BER_Error;
          tbs_len -= ti.nhdr;
          if (tbs_len < ti.length)
            return KSBA_BER_Error; 
          tbs_len -= ti.length;
        }
      /* fixme: we should also check the outer data length here and in
         the follwing code.  It might however be easier to to thsi at
         the end of this sequence */
      if (ti.length != 1)
        return KSBA_Unsupported_CRL_Version; 
      if ( (c=read_byte (crl->reader)) == -1)
        return KSBA_Read_Error;
      if ( !(c == 0 || c == 1) )
        return KSBA_Unsupported_CRL_Version;
      crl->crl_version = c;
      err = _ksba_ber_read_tl (crl->reader, &ti);
      if (err)
        return err;
    }

  /* read the algorithm identifier */
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE
         && ti.is_constructed) )
    return KSBA_Invalid_CRL_Object;
  if (!tbs_ndef)
    {
      if (tbs_len < ti.nhdr)
        return KSBA_BER_Error;
      tbs_len -= ti.nhdr;
      if (!ti.ndef && tbs_len < ti.length)
        return KSBA_BER_Error;
      tbs_len -= ti.length;
    }
  if (ti.nhdr + ti.length >= DIM(tmpbuf))
    return KSBA_Object_Too_Large;
  memcpy (tmpbuf, ti.buf, ti.nhdr);
  err = read_buffer (crl->reader, tmpbuf+ti.nhdr, ti.length);
  if (err)
    return err;
  
  xfree (crl->algo.oid); crl->algo.oid = NULL;
  xfree (crl->algo.parm); crl->algo.parm = NULL;
  err = _ksba_parse_algorithm_identifier2 (tmpbuf, ti.nhdr+ti.length, &nread,
                                           &crl->algo.oid,
                                           &crl->algo.parm,
                                           &crl->algo.parmlen);
  if (err)
    return err;
  assert (nread <= ti.nhdr + ti.length);
  if (nread < ti.nhdr + ti.length)
    return KSBA_Object_Too_Short;

  /* read the name */
  err = create_and_run_decoder (crl->reader, 
                                "TMTTv2.CertificateList.tbsCertList.issuer",
                                &crl->issuer.root,
                                &crl->issuer.image,
                                &crl->issuer.imagelen);
  if (err)
    return err;
  if (!tbs_ndef)
    {
      if (tbs_len < crl->issuer.imagelen)
        return KSBA_BER_Error;
      tbs_len -= crl->issuer.imagelen;
    }

  
  /* read the thisUpdate time */
  err = _ksba_ber_read_tl (crl->reader, &ti);
  if (err)
    return err;
  if ( !(ti.class == CLASS_UNIVERSAL
         && (ti.tag == TYPE_UTC_TIME || ti.tag == TYPE_GENERALIZED_TIME)
         && !ti.is_constructed) )
    return KSBA_Invalid_CRL_Object;
  if (!tbs_ndef)
    {
      if (tbs_len < ti.nhdr)
        return KSBA_BER_Error;
      tbs_len -= ti.nhdr;
      if (!ti.ndef && tbs_len < ti.length)
        return KSBA_BER_Error;
      tbs_len -= ti.length;
    }
  if (ti.nhdr + ti.length >= DIM(tmpbuf))
    return KSBA_Object_Too_Large;
  memcpy (tmpbuf, ti.buf, ti.nhdr);
  err = read_buffer (crl->reader, tmpbuf+ti.nhdr, ti.length);
  if (err)
    return err;
  crl->this_update = _ksba_asntime_to_epoch (tmpbuf+ti.nhdr, ti.length);

  /* read the optional nextUpdate time */
  err = _ksba_ber_read_tl (crl->reader, &ti);
  if (err)
    return err;
  if ( ti.class == CLASS_UNIVERSAL
       && (ti.tag == TYPE_UTC_TIME || ti.tag == TYPE_GENERALIZED_TIME)
         && !ti.is_constructed )
    {
      if (!tbs_ndef)
        {
          if (tbs_len < ti.nhdr)
            return KSBA_BER_Error;
          tbs_len -= ti.nhdr;
          if (!ti.ndef && tbs_len < ti.length)
            return KSBA_BER_Error;
          tbs_len -= ti.length;
        }
      if (ti.nhdr + ti.length >= DIM(tmpbuf))
        return KSBA_Object_Too_Large;
      memcpy (tmpbuf, ti.buf, ti.nhdr);
      err = read_buffer (crl->reader, tmpbuf+ti.nhdr, ti.length);
      if (err)
        return err;
      crl->next_update = _ksba_asntime_to_epoch (tmpbuf+ti.nhdr, ti.length);
      err = _ksba_ber_read_tl (crl->reader, &ti);
      if (err)
        return err;
    }

  /* read the first sequence tag of the optional SEQ of SEQ */
  if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE
      && ti.is_constructed )
    { /* yes, there is one */
      if (!tbs_ndef)
        {
          if (tbs_len < ti.nhdr)
            return KSBA_BER_Error;
          tbs_len -= ti.nhdr;
          /* fixme: tbslen is 2 bytes too short at this point  */
/*            if (!ti.ndef && tbs_len < ti.length) */
/*              return KSBA_BER_Error; */
/*            tbs_len -= ti.length;  */
        }
      crl->state.have_seqseq = 1;
      crl->state.seqseq_ndef = ti.ndef;
      crl->state.seqseq_len  = ti.length;
      /* and read the next */
      err = _ksba_ber_read_tl (crl->reader, &ti);
      if (err)
        return err;
    }
  
  /* we need to save some stuff for the next round */
  crl->state.ti = ti;
  crl->state.outer_ndef = outer_ndef;
  crl->state.outer_len = outer_len;
  crl->state.tbs_ndef = tbs_ndef;
  crl->state.tbs_len = tbs_len;

  return 0;
}


/* Parse the revokedCertificates SEQEUNCE of SEQUENCE using a custom
   parser for efficiency and return after each entry */
static KsbaError
parse_crl_entry (KsbaCRL crl, int *got_entry)
{
  KsbaError err;
  struct tag_info ti = crl->state.ti;
  unsigned long seqseq_len= crl->state.seqseq_len;
  int seqseq_ndef         = crl->state.seqseq_ndef;
  unsigned long len;
  int ndef;
  unsigned char tmpbuf[500]; /* for time and serial number */
  char numbuf[22];
  int numbuflen;

  /* check the length to see whether we are at the end of the seq but do
     this only when we know that we have this optional seq of seq. */
  if (!crl->state.have_seqseq)
    return 0; /* ready (no entries at all) */

  if (!seqseq_ndef && !seqseq_len)
    return 0; /* ready */

  /* if this is not a SEQUENCE the CRL is invalid */
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE
         && ti.is_constructed) )
    return KSBA_Invalid_CRL_Object;
  if (!seqseq_ndef)
    {
      if (seqseq_len < ti.nhdr)
        return KSBA_BER_Error;
      seqseq_len -= ti.nhdr;
      if (!ti.ndef && seqseq_len < ti.length)
        return KSBA_BER_Error;
      seqseq_len -= ti.length;
    }
  ndef = ti.ndef;
  len  = ti.length;

  /* get the serial number */
  err = _ksba_ber_read_tl (crl->reader, &ti);
  if (err)
    return err;
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_INTEGER
         && !ti.is_constructed) )
    return KSBA_Invalid_CRL_Object;
  if (!ndef)
    {
      if (len < ti.nhdr)
        return KSBA_BER_Error;
      len -= ti.nhdr;
      if (!ti.ndef && len < ti.length)
        return KSBA_BER_Error;
      len -= ti.length;
    }
  if (ti.nhdr + ti.length >= DIM(tmpbuf))
    return KSBA_Object_Too_Large;
  memcpy (tmpbuf, ti.buf, ti.nhdr);
  err = read_buffer (crl->reader, tmpbuf+ti.nhdr, ti.length);
  if (err)
    return err;

  xfree (crl->item.serial);
  sprintf (numbuf,"(%u:", (unsigned int)ti.length);
  numbuflen = strlen (numbuf);
  crl->item.serial = xtrymalloc (numbuflen + ti.length + 2);
  if (!crl->item.serial)
    return KSBA_Out_Of_Core;
  strcpy (crl->item.serial, numbuf);
  memcpy (crl->item.serial+numbuflen, tmpbuf+ti.nhdr, ti.length);
  crl->item.serial[numbuflen + ti.length] = ')';
  crl->item.serial[numbuflen + ti.length + 1] = 0;

  /* get the revocation time */
  err = _ksba_ber_read_tl (crl->reader, &ti);
  if (err)
    return err;
  if ( !(ti.class == CLASS_UNIVERSAL
         && (ti.tag == TYPE_UTC_TIME || ti.tag == TYPE_GENERALIZED_TIME)
         && !ti.is_constructed) )
    return KSBA_Invalid_CRL_Object;
  if (!ndef)
    {
      if (len < ti.nhdr)
        return KSBA_BER_Error;
      len -= ti.nhdr;
      if (!ti.ndef && len < ti.length)
        return KSBA_BER_Error;
      len -= ti.length;
    }
  if (ti.nhdr + ti.length >= DIM(tmpbuf))
    return KSBA_Object_Too_Large;
  memcpy (tmpbuf, ti.buf, ti.nhdr);
  err = read_buffer (crl->reader, tmpbuf+ti.nhdr, ti.length);
  if (err)
    return err;
  crl->item.revocation_date =
    _ksba_asntime_to_epoch (tmpbuf+ti.nhdr, ti.length);

  /* if there is still space we must parse the optional entryExtensions */
  if (!ndef && len)
    {
      /* fixme */

    }

  /* read ahead */
  err = _ksba_ber_read_tl (crl->reader, &ti);
  if (err)
    return err;

  *got_entry = 1;

  /* Fixme: the seqseq length is not correct if any element was ndef'd */
  crl->state.ti = ti;
  crl->state.seqseq_ndef = seqseq_ndef;
  crl->state.seqseq_len  = seqseq_len;

  return 0;
}


/* This function is used when a [0] tag was encountered to read the
   crlExtensions */
static KsbaError 
parse_crl_extensions (KsbaCRL crl)
{ 
  struct tag_info ti = crl->state.ti;

  /* if we do not have a tag [0] we are done with this */
  if (!(ti.class == CLASS_CONTEXT && ti.tag == 0 && ti.is_constructed))
    return 0;
  
  /* fixme XXXX */

  return 0;
}

/* Parse the signatureAlgorithm and the signature */
static KsbaError
parse_signature (KsbaCRL crl)
{
  /* fixme XXXX */

  return 0;
}


/* The actual parser which should be used with a new CRL object and
   run in a loop until the the KSBA_SR_READY is encountered */
KsbaError 
ksba_crl_parse (KsbaCRL crl, KsbaStopReason *r_stopreason)
{
  enum { 
    sSTART,
    sCRLENTRY,
    sCRLEXT,
    sERROR
  } state = sERROR;
  KsbaStopReason stop_reason;
  KsbaError err = 0;
  int got_entry = 0;

  if (!crl || !r_stopreason)
    return KSBA_Invalid_Value;

  if (!crl->any_parse_done)
    { /* first time initialization of the stop reason */
      *r_stopreason = 0;
      crl->any_parse_done = 1;
    }

  /* Calculate state from last reason */
  stop_reason = *r_stopreason;
  *r_stopreason = KSBA_SR_RUNNING;
  switch (stop_reason)
    {
    case 0:
      state = sSTART;
      break;
    case KSBA_SR_BEGIN_ITEMS:
    case KSBA_SR_GOT_ITEM:
      state = sCRLENTRY;
      break;
    case KSBA_SR_END_ITEMS:
      state = sCRLEXT;
      break;
    case KSBA_SR_RUNNING:
      err = KSBA_Invalid_State;
      break;
    default:
      err = KSBA_Bug;
      break;
    }
  if (err)
    return err;

  /* Do the action */
  switch (state)
    {
    case sSTART:
      err = parse_to_next_update (crl);
      break;
    case sCRLENTRY:
      err = parse_crl_entry (crl, &got_entry);
      break;
    case sCRLEXT:
      err = parse_crl_extensions (crl);
      if (!err)
        err = parse_signature (crl);
      break;
    default:
      err = KSBA_Invalid_State;
      break;
    }
  if (err)
    return err;

  /* Calculate new stop reason */
  switch (state)
    {
    case sSTART:
      stop_reason = KSBA_SR_BEGIN_ITEMS;
      break;
    case sCRLENTRY:
      stop_reason = got_entry? KSBA_SR_GOT_ITEM : KSBA_SR_END_ITEMS;
      break;
    case sCRLEXT:
      stop_reason = KSBA_SR_READY;
      break;
    default:
      break;
    }
  
  *r_stopreason = stop_reason;
  return 0;
}
