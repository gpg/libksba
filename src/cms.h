/* cms.h - Internal definitions for the CMS functions
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

#ifndef CMS_H
#define CMS_H 1

#include "ksba.h"

#ifndef HAVE_TYPEDEFD_ASNNODE
typedef struct asn_node_struct *AsnNode;  /* FIXME: should not go here */
#define HAVE_TYPEDEFD_ASNNODE
#endif


struct oidlist_s {
  struct oidlist_s *next;
  char *oid;
};

struct certlist_s {
  struct certlist_s *next;
  KsbaCert cert;
  int  msg_digest_len;  /* used length of .. */
  char msg_digest[32];  /* enough space to store a SHA-256 hash */
  struct {
    AsnNode root;
    unsigned char *image;
  } attr; /* temporary storage of signed attributes */
};


struct ksba_cms_s {
  KsbaError last_error;

  KsbaReader reader;
  KsbaWriter writer;

  void (*hash_fnc)(void *, const void *, size_t);
  void *hash_fnc_arg;

  KsbaStopReason stop_reason;
  
  struct {
    char *oid;
    unsigned long length;
    int ndef;
    KsbaContentType ct;
    KsbaError (*handler)(KsbaCMS);
  } content;

  struct {
    unsigned char *digest;
    int digest_len;
  } data;

  int cms_version;   
  
  struct oidlist_s *digest_algos;
  struct certlist_s *cert_list;
  char *encap_cont_type; /* EncapsulatedContentInfo.contentType as string */
  int detached_signature; /* no actual data */

  struct {
    AsnNode root;  /* root of the tree with the values */
    unsigned char *image;
    size_t imagelen;
    struct {
      char *digest_algo;
    } cache;
  } signer_info;  

  struct {
    char *algo;
    unsigned char *value;
    size_t valuelen;
  } sig_val;

};


/*-- cms.c --*/


/*-- cms-parser.c --*/
KsbaError _ksba_cms_parse_content_info (KsbaCMS cms);
KsbaError _ksba_cms_parse_signed_data_part_1 (KsbaCMS cms);
KsbaError _ksba_cms_parse_signed_data_part_2 (KsbaCMS cms);



#endif /*CMS_H*/


