/* asn1-der.h - definitions for DER parsing
 *      Copyright (C) 2000,2001 Fabio Fiorina
 *      Copyright (C) 2001 Free Software Foundation, Inc.
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef ASN1_DER_H
#define ASN1_DER_H

#include "asn1-func.h"

#define UNIVERSAL        0x00
#define APPLICATION      0x40
#define CONTEXT_SPECIFIC 0x80
#define PRIVATE          0xC0
#define STRUCTURED       0x20


void
_asn1_octet_der(unsigned char *str,int str_len,unsigned char *der,int *der_len);

int
_asn1_get_octet_der(unsigned char *der,int *der_len,unsigned char *str,int str_size, int *str_len);

void
_asn1_bit_der(unsigned char *str,int bit_len,unsigned char *der,int *der_len);

int
_asn1_get_bit_der(unsigned char *der,int *der_len,unsigned char *str, int str_size, int *bit_len);

int 
asn1_create_der(node_asn *root,char *name,unsigned char *der,int *len);

int 
asn1_get_der(node_asn *root,unsigned char *der,int len);

int 
asn1_get_start_end_der(node_asn *root,unsigned char *der,int len,char *name_element,int *start, int *end);


#endif /*ASN1_DER_H*/





