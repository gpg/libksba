/* asn1-func.h - definitions for asn1-func.c
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

#ifndef ASN1_FUNC_H
#define ASN1_FUNC_H

/* Error Codes */
enum {
  ASN_OK                  =  0,
  ASN_FILE_NOT_FOUND      =  1,
  ASN_ELEMENT_NOT_FOUND   =  2,
  ASN_IDENTIFIER_NOT_FOUND=  3,
  ASN_DER_ERROR           =  4,
  ASN_VALUE_NOT_FOUND     =  5,
  ASN_GENERIC_ERROR       =  6,
  ASN_VALUE_NOT_VALID     =  7,
  ASN_TAG_ERROR           =  8,
  ASN_TAG_IMPLICIT        =  9,
  ASN_ERROR_TYPE_ANY      = 10,
  ASN_SYNTAX_ERROR        = 11,
  ASN_MEM_ERROR           = 12
};


typedef enum {
  TYPE_NONE = 0,
  TYPE_BOOLEAN = 1,
  TYPE_INTEGER = 2,
  TYPE_BIT_STRING = 3,
  TYPE_OCTET_STRING = 4,
  TYPE_OBJECT_ID = 6,
  TYPE_SEQUENCE = 16,
  TYPE_SET = 17,
  TYPE_CONSTANT,
  TYPE_IDENTIFIER,
  TYPE_TAG,
  TYPE_DEFAULT,
  TYPE_SIZE,
  TYPE_SEQUENCE_OF,
  TYPE_ANY,
  TYPE_SET_OF,
  TYPE_DEFINITIONS,
  TYPE_TIME,
  TYPE_CHOICE,
  TYPE_IMPORTS,
  TYPE_NULL,
  TYPE_ENUMERATED
} node_type_t;


enum tag_class {
  CLASS_UNIVERSAL = 0,
  CLASS_APPLICATION = 1,
  CLASS_CONTEXT = 2,
  CLASS_PRIVATE =3
};

struct node_flag_s {
  enum tag_class class;
  int explicit:1;
  int implicit:1;
  int has_imports:1;
  int assignment:1;
  int one_param:1;
  int has_tag:1; 
  int has_size:1;
  int has_list:1;
  int has_min_max:1;
  int has_defined_by:1;
  int is_false:1;
  int is_true:1;
  int is_default:1;
  int is_optional:1;
  int is_utc_time:1;
  int is_set:1;       /* check whether this is needed */
  int is_not_used:1;  /* check whether this is needed */
  int help_down:1;    /* helper for create_tree */
  int help_right:1;
};

/******************************************************/
/* Structure definition used for the node of the tree */
/* that rappresent an ASN.1 DEFINITION.               */
/******************************************************/
typedef struct asn_node_struct *AsnNode; 
struct asn_node_struct {
  char *name;                    /* Node name */
  node_type_t type;   
  struct node_flag_s flags;

  unsigned char *value;          /* Node value */
  AsnNode down;                  /* Pointer to the son node */
  AsnNode right;                 /* Pointer to the brother node */
  AsnNode left;                  /* Pointer to the next list element */ 
  AsnNode link_next;             /* to keep track of all nodes in a tree */
}; 

/* Structure to keep an entire ASN.1 parse tree and associated information */
struct ksba_asn_tree_s {
  AsnNode parse_tree;
  AsnNode node_list;  /* for easier release of all nodes */
  char filename[1];
};


typedef struct static_struct_asn {
  char *name;                    /* Node name */
  node_type_t type;             /* Node type */
  struct node_flag_s flags;
  unsigned char *value;          /* Node value */
} static_asn;




/***************************************/
/*  Functions used by ASN.1 parser     */
/***************************************/
void _ksba_asn_set_value (AsnNode node, const void *value, unsigned int len);
void _ksba_asn_set_name (AsnNode node, const char *name);
AsnNode _ksba_asn_walk_tree (AsnNode root, AsnNode node);
AsnNode _ksba_asn_find_node(AsnNode pointer,char *name);
int _ksba_asn_check_identifier(AsnNode node);
int _ksba_asn_change_integer_value(AsnNode node);
int _ksba_asn_delete_not_used(AsnNode node);
int _ksba_asn_expand_object_id(AsnNode node);
void _ksba_asn_set_default_tag (AsnNode node);
void _ksba_asn_type_set_config (AsnNode node);


/*-- asn1-func.c --*/
int ksba_asn_create_structure (AsnNode root, char *source_name,
                               AsnNode*pointer , char *dest_name);
int ksba_asn_delete_structure (AsnNode root);
int ksba_asn1_create_tree (const static_asn *root,AsnNode*pointer);
int ksba_asn_read_value(AsnNode root,char *name,unsigned char *value,int *len);
int ksba_asn_write_value(AsnNode root,char *name,unsigned char *value,int len);




#endif /*ASN1_FUNC_H*/


