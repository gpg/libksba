/* cert.h - Internal definitions for cert.c
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

#ifndef CERT_H
#define CERT_H 1

#include "asn1-func.h"


struct cert_extn_info {
  char *oid;
  int crit;
  int off, len;
};


struct ksba_cert_s {
  int initialized;
  int ref_count;
  KsbaAsnTree asn_tree;
  AsnNode root;  /* root of the tree with the values */
  unsigned char *image;
  size_t imagelen;
  KsbaError last_error;
  struct {
    char *digest_algo;
    int  extns_valid;
    int  n_extns;
    struct cert_extn_info *extns;
  } cache;
};


int _ksba_cert_cmp (KsbaCert a, KsbaCert b);


#endif /*CERT_H*/

