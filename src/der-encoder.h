/* der-encoder.h - Definitions for the Distinguished Encoding Rules Encoder
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

#ifndef DER_ENCODER_H
#define DER_ENCODER_H 1

#include "asn1-func.h"

struct der_encoder_s;
typedef struct der_encoder_s *DerEncoder;

DerEncoder _ksba_der_encoder_new (void);
void       _ksba_der_encoder_release (DerEncoder d);

KsbaError _ksba_der_encoder_set_module (DerEncoder d, KsbaAsnTree module);
KsbaError _ksba_der_encoder_set_writer (DerEncoder d, KsbaWriter w);


KsbaError _ksba_der_write_integer (KsbaWriter w, const unsigned char *value);
KsbaError _ksba_der_write_algorithm_identifier (
            KsbaWriter w, const char *oid, const void *parm, size_t parmlen);



KsbaError _ksba_der_copy_tree (AsnNode dst,
                               AsnNode src, const unsigned char *srcimage);



KsbaError _ksba_der_store_time (AsnNode node, const ksba_isotime_t atime);
KsbaError _ksba_der_store_string (AsnNode node, const char *string);
KsbaError _ksba_der_store_integer (AsnNode node, const unsigned char *value);
KsbaError _ksba_der_store_oid (AsnNode node, const char *oid);
KsbaError _ksba_der_store_octet_string (AsnNode node,
                                        const char *buf, size_t len);
KsbaError _ksba_der_store_null (AsnNode node);


KsbaError _ksba_der_encode_tree (AsnNode root,
                                 unsigned char **r_image, size_t *r_imagelen);



#endif /*DER_ENCODER_H*/


