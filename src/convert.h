/* convert.h 
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

#ifndef CONVERT_H
#define CONVERT_H

#include "asn1-func.h"

/*-- time.c --*/
time_t _ksba_asntime_to_epoch (const char *buffer, size_t length);

/*-- dn.c --*/
KsbaError _ksba_dn_to_str (const unsigned char *image, AsnNode node,
                           char **r_string);
KsbaError _ksba_dn_from_str (const char *string, char **rbuf, size_t *rlength);

/*-- oid.c --*/
char *_ksba_oid_node_to_str (const unsigned char *image, AsnNode node);


/*-- name.c --*/
KsbaError _ksba_name_new_from_der (KsbaName *r_name,
                                   const unsigned char *image,
                                   size_t imagelen);


#endif /*CONVERT_H*/




