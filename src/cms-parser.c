/* cms-parse.c - parse cryptographic message syntax
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

/*
   We handle CMS by using a handcrafted parser for the outer
   structures and the generic parser of the parts we can handle in
   memory.  Extending the generic parser to allow hooks for indefinite
   length objects and to auto select the object depending on the
   content type OID is too complicated.
*/


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "util.h"

#include "cms.h"
#include "asn1-func.h" /* need some constants */
#include "ber-decoder.h"
#include "ber-help.h"
#include "keyinfo.h"

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



/* Parse this structure and return the oid of the content.  The read
   position is then located at the value of content.  This fucntion is
   the core for parsing ContentInfo and EncapsulatedContentInfo.

   ContentInfo ::= SEQUENCE {
      contentType ContentType, 
      content [0] EXPLICIT ANY DEFINED BY contentType 
   }
   ContentType ::= OBJECT IDENTIFIER

   Returns: 0 on success or an error code. Other values are returned
   by the parameters.

*/
static KsbaError
parse_content_info (KsbaReader reader,
                    unsigned long *r_len, int *r_ndef,
                    char **r_oid, int *has_content)
{
  struct tag_info ti;
  KsbaError err;
  int content_ndef;
  unsigned long content_len;
  unsigned char oidbuf[100]; /* pretty large for an OID */
  char *oid = NULL;
  int c, i;

  /* read the sequence triplet */
  err = _ksba_ber_read_tl (reader, &ti);
  if (err)
    return err;
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE
         && ti.is_constructed) )
    return KSBA_Invalid_CMS_Object;
  content_len = ti.length; 
  content_ndef = ti.ndef;
  if (!content_ndef && content_len < 3)
    return KSBA_Object_Too_Short; /* to encode an OID */

  /* read the OID */
  err = _ksba_ber_read_tl (reader, &ti);
  if (err)
    return err;
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OBJECT_ID
         && !ti.is_constructed && ti.length) )
    return KSBA_Invalid_CMS_Object; 
  if (!content_ndef)
    {
      if (content_len < ti.nhdr)
        return KSBA_BER_Error; /* triplet header larger that sequence */
      content_len -= ti.nhdr;
      if (content_len < ti.length)
        return KSBA_BER_Error; /* triplet larger that sequence */
      content_len -= ti.length;
    }
  
  for (i=0; i < ti.length; i++)
    {
      if (i == DIM(oidbuf))
        return KSBA_Object_Too_Large;
      if ( (c=read_byte (reader)) == -1)
        return KSBA_Read_Error;
      oidbuf[i] = c;
    }
  oid = ksba_oid_to_str (oidbuf, i);
  if (!oid)
    return KSBA_Out_Of_Core;
  
  /* now read the explicit tag 0 */
  err = _ksba_ber_read_tl (reader, &ti);
  if (err)
    {
      xfree (oid);
      return err;
    }

  if ( ti.class == CLASS_CONTEXT && ti.tag == 0 && ti.is_constructed )
    {
      *has_content = 1;
    }
  else if ( ti.class == CLASS_UNIVERSAL && ti.tag == 0 && !ti.is_constructed )
    {
      *has_content = 0; /* this is optional - allow NUL tag */
    }
  else /* neither [0] nor NULL */
    {
      xfree (oid);
      return KSBA_Invalid_CMS_Object; 
    }
  if (!content_ndef)
    {
      if (content_len < ti.nhdr)
        return KSBA_BER_Error; /* triplet header larger that sequence */
      content_len -= ti.nhdr;
      if (!ti.ndef && content_len < ti.length)
        return KSBA_BER_Error; /* triplet larger that sequence */
    }

  *r_len = content_len;
  *r_ndef = content_ndef;
  *r_oid = oid;
  return 0;
}



/* Parse this structure and return the oid of the content.  The read
   position is then located at the value of content.

   ContentInfo ::= SEQUENCE {
      contentType ContentType, 
      content [0] EXPLICIT ANY DEFINED BY contentType 
   }
   ContentType ::= OBJECT IDENTIFIER

   Returns: 0 on success or an error code.  On success the OID and the
   length values are stored in the cms structure.
*/
KsbaError
_ksba_cms_parse_content_info (KsbaCMS cms)
{
  KsbaError err;
  int has_content;
  int content_ndef;
  unsigned long content_len;
  char *oid;

  err = parse_content_info (cms->reader, &content_len, &content_ndef,
                            &oid, &has_content);
  if (err)
    { /* return a more meaningful error message.  This way the caller
         can pass arbitrary data to the function and get back an error
         that this is not CMS instead of BER Error */
      if (err == KSBA_BER_Error || err == KSBA_Invalid_CMS_Object
          || err == KSBA_Object_Too_Short)
        err = KSBA_No_CMS_Object;
      return err;
    }
  if (!has_content)
    return KSBA_No_CMS_Object; /* It is not optional here */
  cms->content.length = content_len;
  cms->content.ndef = content_ndef;
  xfree (cms->content.oid);
  cms->content.oid = oid;
  return 0;
}


/* Parse a structure:

   SignedData ::= SEQUENCE {
     version INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4) }),
     digestAlgorithms SET OF AlgorithmIdentifier,
     encapContentInfo EncapsulatedContentInfo,
     certificates [0] IMPLICIT CertificateSet OPTIONAL,
     crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
     signerInfos SignerInfos }
   
   AlgorithmIdentifier ::= SEQUENCE {
    algorithm    OBJECT IDENTIFIER,
    parameters   ANY DEFINED BY algorithm OPTIONAL
   }

*/
KsbaError
_ksba_cms_parse_signed_data_part_1 (KsbaCMS cms)
{
  struct tag_info ti;
  KsbaError err;
  int signed_data_ndef;
  unsigned long signed_data_len;
  int algo_set_ndef;
  unsigned long algo_set_len;
  int encap_cont_ndef;
  unsigned long encap_cont_len;
  int has_content;
  char *oid;
  int c;
  char *p, *buffer;
  unsigned long off, len;

  /* read the sequence triplet */
  err = _ksba_ber_read_tl (cms->reader, &ti);
  if (err)
    return err;
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE
         && ti.is_constructed) )
    return KSBA_Invalid_CMS_Object;
  signed_data_len = ti.length; 
  signed_data_ndef = ti.ndef;
  if (!signed_data_ndef && signed_data_len < 3)
    return KSBA_Object_Too_Short; /*to encode the version*/

  /* read the version integer */
  err = _ksba_ber_read_tl (cms->reader, &ti);
  if (err)
    return err;
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_INTEGER
         && !ti.is_constructed && ti.length) )
    return KSBA_Invalid_CMS_Object; 
  if (!signed_data_ndef)
    {
      if (signed_data_len < ti.nhdr)
        return KSBA_BER_Error; /* triplet header larger that sequence */
      signed_data_len -= ti.nhdr;
      if (signed_data_len < ti.length)
        return KSBA_BER_Error; /* triplet larger that sequence */
      signed_data_len -= ti.length;
    }
  if (ti.length != 1)
    return KSBA_Unsupported_CMS_Version; 
  if ( (c=read_byte (cms->reader)) == -1)
    return KSBA_Read_Error;
  if ( !(c == 0 || c == 1 || c == 2 || c == 3 || c == 4) )
    return KSBA_Unsupported_CMS_Version;
  cms->cms_version = c;

  /* read the SET OF algorithmIdentifiers */
  err = _ksba_ber_read_tl (cms->reader, &ti);
  if (err)
    return err;
  if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SET
         && ti.is_constructed) )
    return KSBA_Invalid_CMS_Object;  /* not the expected SET tag */
  if (!signed_data_ndef)
    {
      if (signed_data_len < ti.nhdr)
        return KSBA_BER_Error; /* triplet header larger that sequence */
      signed_data_len -= ti.nhdr;
      if (!ti.ndef && signed_data_len < ti.length)
        return KSBA_BER_Error; /* triplet larger that sequence */
      signed_data_len -= ti.length;
    }
  algo_set_len = ti.length; 
  algo_set_ndef = ti.ndef;
  
  /* fixme: we are not able to read ndef length algorithm indentifiers. */
  if (algo_set_ndef)
    return KSBA_Unsupported_Encoding;
  /* read the entire sequence into a buffer */
  buffer = xtrymalloc (algo_set_len);
  if (!buffer)
    return KSBA_Out_Of_Core;
  if (read_buffer (cms->reader, buffer, algo_set_len))
    {
      xfree (buffer);
      return KSBA_Read_Error;
    }
  p = buffer;
  while (algo_set_len)
    {
      size_t nread;
      struct oidlist_s *ol;

      err = _ksba_parse_algorithm_identifier (p, algo_set_len, &nread, &oid);
      if (err)
        {
          xfree (buffer);
          return err;
        }
      assert (nread <= algo_set_len);
      algo_set_len -= nread;
      p += nread;
      /* store the oid */
      ol = xtrymalloc (sizeof *ol);
      if (!ol)
        {
          xfree (oid);
          return KSBA_Out_Of_Core;
        }
      ol->oid = oid;
      ol->next = cms->digest_algos;
      cms->digest_algos = ol;
    }
  xfree (buffer); buffer = NULL;

  /* Now for the encapsulatedContentInfo */
  off = ksba_reader_tell (cms->reader);
  err = parse_content_info (cms->reader,
                            &encap_cont_len, &encap_cont_ndef, 
                            &oid, &has_content);
  if (err)
    return err;
  cms->encap_cont_type = oid; 
  cms->detached_signature = !has_content;
  if (!signed_data_ndef)
    {
      len = ksba_reader_tell (cms->reader) - off;
      if (signed_data_len < len)
        return KSBA_BER_Error; /* parsed content info larger that sequence */
      signed_data_len -= len;
      if (!encap_cont_ndef && signed_data_len < encap_cont_len)
        return KSBA_BER_Error; /* triplet larger that sequence */
    }
  
  /* Fixme: Do we ween to skip the OCTECT STRING tag here or should we
     just use whatever comes? */

  /* FIXME: need to store the content length info */

  /* We have to stop here so that the caller can set up the hashing etc. */
  return 0;
}

/* Continue parsing of the structure we started to parse with the
   part_1 function.  We expect to be right at the certificates tag.  */
KsbaError
_ksba_cms_parse_signed_data_part_2 (KsbaCMS cms)
{
  struct tag_info ti;
  KsbaError err;

  /* read the next triplet which is either a [0], a [1] or a SET OF
     (signerInfo) */
  err = _ksba_ber_read_tl (cms->reader, &ti);
  if (err)
    return err;

  if (ti.class == CLASS_CONTEXT && ti.tag == 0 && ti.is_constructed)
    {  /* implicit SET OF certificateSet with elements of CHOICE, but
          we assume the first choice which is a Certificate; all other
          choices are obsolete.  We are now parsing a set of
          certificates which we do by utilizing the ksba_cert code. */
      KsbaCert cert;

      if (ti.ndef)
        return KSBA_Unsupported_Encoding;
      
      for (;;)
        {
          struct certlist_s *cl;

          /* first see whether this is really a sequence */
          err = _ksba_ber_read_tl (cms->reader, &ti);
          if (err)
            return err;
          if ( !(ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_SEQUENCE
                 && ti.is_constructed))
            break; /* not a sequence, so we are ready with the set */
          /* We must unread so that the standard parser sees the sequence */
          err = ksba_reader_unread (cms->reader, ti.buf, ti.nhdr);
          if (err)
            return err;
          /* Use the standard certificate parser */
          cert = ksba_cert_new ();
          if (!cert)
            return KSBA_Out_Of_Core;
          err = ksba_cert_read_der (cert, cms->reader);
          if (err)
            {
              ksba_cert_release (cert);
              return err;
            }
          cl = xtrymalloc (sizeof *cl);
          if (!cl)
            {
              ksba_cert_release (cert);
              return KSBA_Out_Of_Core;
            }
          cl->cert = cert;
          cl->next = cms->cert_list;
          cms->cert_list = cl;
        }
    }
      
  if (ti.class == CLASS_CONTEXT && ti.tag == 1 && ti.is_constructed)
    {  /* implicit SET OF certificateList.  We should delegate the
          parsing to a - not yet existing - ksba_crl module.  CRLs are
          quite importatnt for other applications too so we should
          provide a nice interface */
      fprintf (stderr,"ERROR: Can't handle CRLs yet\n");

      err = _ksba_ber_read_tl (cms->reader, &ti);
      if (err)
        return err;
    }

  /* expect a SET OF signerInfo */
  if ( !(ti.class == CLASS_UNIVERSAL
         && ti.tag == TYPE_SET && ti.is_constructed))
    return KSBA_Invalid_CMS_Object; 

  {
    KsbaAsnTree cms_tree;
    BerDecoder decoder;

    err = ksba_asn_parse_file ("/home/wk/work/libksba/src/cms.asn",
                               &cms_tree, 0);
    if (err)
      return err;

    decoder = _ksba_ber_decoder_new ();
    if (!decoder)
      {
        ksba_asn_tree_release (cms_tree);
        return KSBA_Out_Of_Core;
      }

    err = _ksba_ber_decoder_set_reader (decoder, cms->reader);
    if (err)
      {
        ksba_asn_tree_release (cms_tree);
        _ksba_ber_decoder_release (decoder);
        return err;
      }

    err = _ksba_ber_decoder_set_module (decoder, cms_tree);
    if (err)
      {
        ksba_asn_tree_release (cms_tree);
        _ksba_ber_decoder_release (decoder);
        return err;
      }

    err = _ksba_ber_decoder_decode (decoder, 
                                    "CryptographicMessageSyntax.SignerInfos",
                                    &cms->signer_info.root,
                                    &cms->signer_info.image,
                                    &cms->signer_info.imagelen);
    
    _ksba_ber_decoder_release (decoder);
    ksba_asn_tree_release (cms_tree);
    if (err)
      return err;
  }

  return 0;
}





