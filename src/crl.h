/* crl.h - Internal definitions for the CRL Parser
 *      Copyright (C) 2002 g10 Code GmbH
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

#ifndef CRL_H
#define CRL_H 1

#include "ksba.h"

#ifndef HAVE_TYPEDEFD_ASNNODE
typedef struct asn_node_struct *AsnNode;  /* FIXME: should not go here */
#define HAVE_TYPEDEFD_ASNNODE
#endif

struct ksba_crl_s {
  KsbaError last_error;

  KsbaReader reader;
  int any_parse_done;

  void (*hash_fnc)(void *, const void *, size_t);
  void *hash_fnc_arg;

  struct {
    struct tag_info ti;
    unsigned long outer_len, tbs_len, seqseq_len;
    int outer_ndef, tbs_ndef, seqseq_ndef;
    int have_seqseq;
  } state;

  int crl_version;
  struct {
    char *oid;
    char *parm;
    size_t parmlen;
  } algo;
  struct {
    AsnNode root;  /* root of the tree with the values */
    unsigned char *image;
    size_t imagelen;
  } issuer;
  ksba_isotime_t this_update;
  ksba_isotime_t next_update;

  struct {
    KsbaSexp serial;
    KsbaCRLReason reason;
    ksba_isotime_t revocation_date;
  } item;

  KsbaSexp sigval;

  struct {
    int used;
    char buffer[8192]; 
  } hashbuf;

};


/*-- crl.c --*/


#endif /*CRL_H*/


