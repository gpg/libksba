/* ksba.h - X509 library for the Aegypten project
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

#ifndef KSBA_H
#define KSBA_H 1
#ifdef __cplusplus
extern "C" { 
#if 0
 }
#endif
#endif

typedef enum {
  KSBA_No_Error = 0,
  KSBA_General_Error = 1,
  KSBA_Out_Of_Core = 2,
  KSBA_Invalid_Value = 3,
  KSBA_Not_Implemented = 4,
  KSBA_Conflict = 5,
  KSBA_Read_Error = 6,
  KSBA_Write_Error = 7,
  KSBA_Invalid_Attr = 8,
  KSBA_No_Data = 9,
  KSBA_No_Value = 10,
  KSBA_Bug = 11,
  KSBA_BER_Error = 12,
  KSBA_Element_Not_Found = 13,
  KSBA_Identifier_Not_Found = 14,
  KSBA_Value_Not_Found = 15,  /* needed?*/
  KSBA_Syntax_Error = 16,
  KSBA_Invalid_Tag = 17,
  KSBA_Invalid_Length = 18,
} KsbaError;

typedef enum {
  KSBA_ATTR_NONE = 0,
  KSBA_ATTR_FOO = 1,
} KsbaAttr;

#define KSBA_SYM(a) ((sym_ ## a)? sym_ ## a:(sym_ ## a = ksba_make_sym (#a)))


/* X.509 certificates are represented by this object.
 * ksba_cert_new() creates such an object */
struct ksba_cert_s;
typedef struct ksba_cert_s *KsbaCert;

/* This is a reader object vor various purposes
   see ksba_reader_new et al. */
struct ksba_reader_s;
typedef struct ksba_reader_s *KsbaReader;

/* This is an object to store an ASN.1 parse tree as
   create by ksba_asn_parse_file() */
struct ksba_asn_tree_s;
typedef struct ksba_asn_tree_s *KsbaAsnTree;
   

/*-- cert.c --*/
KsbaCert ksba_cert_new (void);
void     ksba_cert_release (KsbaCert cert);


/*-- reader.c --*/
KsbaReader ksba_reader_new (void);
void       ksba_reader_release (KsbaReader r);
int        ksba_reader_error (KsbaReader r);

KsbaError ksba_reader_set_mem (KsbaReader r,
                               const void *buffer, size_t length);
KsbaError ksba_reader_set_fd (KsbaReader r, int fd);
KsbaError ksba_reader_set_file (KsbaReader r, FILE *fp);
KsbaError ksba_reader_set_cb (KsbaReader r, 
                              int (*cb)(void*,char *,size_t,size_t*),
                              void *cb_value );

KsbaError ksba_reader_read (KsbaReader r,
                            char *buffer, size_t length, size_t *nread);


/*-- asn1-parse.y --*/
int ksba_asn_parse_file (const char *filename, KsbaAsnTree *result);
void ksba_asn_tree_release (KsbaAsnTree tree);

/*-- asn1-func.c --*/
void ksba_asn_tree_dump (KsbaAsnTree tree, const char *name, FILE *fp);


#ifdef __cplusplus
}
#endif
#endif /*KSBA_H*/

