/* certreq.h - Internal definitions for pkcs-10 objects
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

#ifndef CERTREQ_H
#define CERTREQ_H 1

#include "ksba.h"

#ifndef HAVE_TYPEDEFD_ASNNODE
typedef struct asn_node_struct *AsnNode;  /* FIXME: should not go here */
#define HAVE_TYPEDEFD_ASNNODE
#endif

struct ksba_certreq_s {
  KsbaError last_error;

  KsbaWriter writer;

  void (*hash_fnc)(void *, const void *, size_t);
  void *hash_fnc_arg;

  int any_build_done;

  struct {
    char *der;
    size_t derlen;
  } subject;
  struct {
    unsigned char *der;
    size_t derlen;
  } key;
  struct {
    unsigned char *der;
    size_t derlen;
  } cri;

  struct {
    char *algo;
    unsigned char *value;
    size_t valuelen;
  } sig_val;


  
};



#endif /*CERTREQ_H*/


