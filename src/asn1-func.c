/* asn1-func.c - Manage ASN.1 definitions
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "ksba.h"
#include "asn1-func.h"
#include "util.h"

static int expand_identifier (AsnNode * node, AsnNode root);
static int type_choice_config (AsnNode  node);

static char *  /* FIXME: This is error prone */
_asn1_ltostr (long v, char *str)
{
  long d, r;
  char temp[20];
  int count, k, start;

  if (v < 0)
    {
      str[0] = '-';
      start = 1;
      v = -v;
    }
  else
    start = 0;

  count = 0;
  do
    {
      d = v / 10;
      r = v - d * 10;
      temp[start + count] = '0' + (char) r;
      count++;
      v = d;
    }
  while (v);

  for (k = 0; k < count; k++)
    str[k + start] = temp[start + count - k - 1];
  str[count + start] = 0;
  return str;
}




static AsnNode 
add_node (node_type_t type)
{
  AsnNode punt;

  punt = xmalloc (sizeof *punt);

  punt->left = NULL;
  punt->name = NULL;
  punt->type = type;
  punt->valuetype = VALTYPE_NULL;
  punt->value.v_cstr = NULL;
  punt->off = -1;
  punt->nhdr = 0;
  punt->len = 0;
  punt->down = NULL;
  punt->right = NULL;
  punt->link_next = NULL;
  return punt;
}



/* Change the value field of the node to the content of buffer value
   of size LEN.  With VALUE of NULL or LEN of 0 the value field is
   deleted */
void
_ksba_asn_set_value (AsnNode node,
                     enum asn_value_type vtype, const void *value, size_t len)
{
  return_if_fail (node);

  if (node->valuetype)
    {
      if (node->valuetype == VALTYPE_CSTR)
        xfree (node->value.v_cstr);
      else if (node->valuetype == VALTYPE_MEM)
        xfree (node->value.v_mem.buf);
      node->valuetype = 0;
    }

  switch (vtype)
    {
    case VALTYPE_NULL:
      break;
    case VALTYPE_BOOL:
      return_if_fail (len);
      node->value.v_bool = !!(const unsigned *)value;
      break;
    case VALTYPE_CSTR:
      node->value.v_cstr = xstrdup (value);
      break;
    case VALTYPE_MEM:
      node->value.v_mem.len = len;
      if (len)
        {
          node->value.v_mem.buf = xmalloc (len);
          memcpy (node->value.v_mem.buf, value, len);
        }
      else
          node->value.v_mem.buf = NULL;
      break;
    case VALTYPE_LONG:
      return_if_fail (sizeof (long) == len);
      node->value.v_long = *(long *)value;
      break;

    case VALTYPE_ULONG:
      return_if_fail (sizeof (unsigned long) == len);
      node->value.v_ulong = *(unsigned long *)value;
      break;

    default:
      return_if_fail (0);
    }
  node->valuetype = vtype;
}

static void
copy_value (AsnNode d, const AsnNode s)
{
  char helpbuf[1];
  const void *buf = NULL;
  size_t len = 0;

  return_if_fail (d != s);

  switch (s->valuetype)
    {
    case VALTYPE_NULL:
      break;
    case VALTYPE_BOOL:
      len = 1;
      helpbuf[1] = s->value.v_bool;
      buf = helpbuf;
      break;
    case VALTYPE_CSTR:
      buf = s->value.v_cstr;
      break;
    case VALTYPE_MEM:
      len = s->value.v_mem.len;
      buf = len? s->value.v_mem.buf : NULL;
      break;
    case VALTYPE_LONG:
      len = sizeof (long);
      buf = &s->value.v_long;
      break;
    case VALTYPE_ULONG:
      len = sizeof (unsigned long);
      buf = &s->value.v_ulong;
      break;

    default:
      return_if_fail (0);
    }
  _ksba_asn_set_value (d, s->valuetype, buf, len);
  d->off = s->off;
  d->nhdr = s->nhdr;
  d->len = s->len;
}

static AsnNode 
copy_node (const AsnNode s)
{
  AsnNode d = add_node (s->type);

  if (s->name)
    d->name = xstrdup (s->name);
  d->flags = s->flags;
  copy_value (d, s);
  return d;
}




/* Change the name field of the node to NAME.  
   NAME may be NULL */
void 
_ksba_asn_set_name (AsnNode node, const char *name)
{
  return_if_fail (node);

  if (node->name)
    {
      xfree (node->name);
      node->name = NULL;
    }

  if (name && *name)
      node->name = xstrdup (name);
}


static AsnNode 
set_right (AsnNode  node, AsnNode  right)
{
  if (node == NULL)
    return node;

  node->right = right;
  if (right)
    right->left = node;
  return node;
}


static AsnNode 
set_down (AsnNode node, AsnNode down)
{
  if (node == NULL)
    return node;

  node->down = down;
  if (down)
    down->left = node;
  return node;
}


void
_ksba_asn_remove_node (AsnNode  node)
{
  if (node == NULL)
    return;

  xfree (node->name);
  if (node->valuetype == VALTYPE_CSTR)
    xfree (node->value.v_cstr);
  else if (node->valuetype == VALTYPE_MEM)
    xfree (node->value.v_mem.buf);
  xfree (node);
}


/* find the node with the given name.  A name part of "?LAST" matches
   the last element of a set of */
AsnNode 
_ksba_asn_find_node (AsnNode root, const char *name)
{
  AsnNode p;
  const char *s;
  char buf[129];
  int i;

  if (!name || !name[0])
    return NULL;

  /* find the first part */
  s = name;
  for (i=0; *s && *s != '.' && i < DIM(buf)-1; s++)
    buf[i++] = *s;
  buf[i] = 0;
  return_null_if_fail (i < DIM(buf)-1);
          
  for (p = root; p && (!p->name || strcmp (p->name, buf)); p = p->right)
    ;

  /* find other parts */
  while (p && *s)
    {
      assert (*s == '.');
      s++; /* skip the dot */

      if (!p->down)
	return NULL; /* not found */
      p = p->down;

      for (i=0; *s && *s != '.' && i < DIM(buf)-1; s++)
        buf[i++] = *s;
      buf[i] = 0;
      return_null_if_fail (i < DIM(buf)-1);

      if (!*buf)
        {
         /* a double dot can be used to get over an unnamed sequence
            in a set - Actually a hack to workaround a bug.  We should
            rethink the entire node naming issue */
        }
      else if (!strcmp (buf, "?LAST"))
	{
	  if (!p)
	    return NULL;
	  while (p->right)
	    p = p->right;
	}
      else
	{
          for (; p && (!p->name || strcmp (p->name, buf)); p = p->right)
            ;
	}
    }
  
  return p;
}


AsnNode 
_asn1_find_left (AsnNode  node)
{
  if ((node == NULL) || (node->left == NULL) || (node->left->down == node))
    return NULL;

  return node->left;
}


static AsnNode 
find_up (AsnNode  node)
{
  AsnNode p;

  if (node == NULL)
    return NULL;

  p = node;
  while ((p->left != NULL) && (p->left->right == p))
    p = p->left;

  return p->left;
}


/**
 * Creates the structures needed to manage the ASN1 definitions. ROOT is
 * a vector created by the asn1-gentable tool.
 * 
 * Input Parameter: 
 *   
 *   static_asn *root: specify vector that contains ASN.1 declarations.
 * 
 * Output Parameter:
 * 
 *   AsnNode *pointer : return the pointer to the structure created by
 *   *ROOT ASN.1 declarations.
 * 
 * Return Value:
 *   ASN_OK: structure created correctly. 
 *   ASN_GENERIC_ERROR: an error occured while structure creation.
 */ 
int
ksba_asn_create_tree (const static_asn * root, AsnNode * pointer)
{
  enum { DOWN, UP, RIGHT } move;
  AsnNode p, p_last = NULL;
  unsigned long k;

  *pointer = NULL;
  move = UP;

  k = 0;
  while (root[k].stringvalue || root[k].type || root[k].name)
    {
      p = add_node (root[k].type);
      p->flags = root[k].flags;
      p->flags.help_down = 0;
      if (root[k].name)
	_ksba_asn_set_name (p, root[k].name);
      if (root[k].stringvalue)
	_ksba_asn_set_value (p, VALTYPE_CSTR, root[k].stringvalue, 0);

      if (*pointer == NULL)
	*pointer = p;

      if (move == DOWN)
	set_down (p_last, p);
      else if (move == RIGHT)
	set_right (p_last, p);

      p_last = p;

      if (root[k].flags.help_down)
	move = DOWN;
      else if (root[k].flags.help_right)
	move = RIGHT;
      else
	{
	  while (1)
	    {
	      if (p_last == *pointer)
		break;

	      p_last = find_up (p_last);

	      if (p_last == NULL)
		break;

	      if (p_last->flags.help_right)
		{
		  p_last->flags.help_right = 0;
		  move = RIGHT;
		  break;
		}
	    }
	}
      k++;
    }

  if (p_last == *pointer)
    {
      _ksba_asn_change_integer_value (*pointer);
      _ksba_asn_expand_object_id (*pointer);
    }
  else
    ksba_asn_delete_structure (*pointer);

  return (p_last == *pointer) ? ASN_OK : ASN_GENERIC_ERROR;
}


static void
print_value (AsnNode node, FILE *fp)
{
  if (!node->valuetype)
    return;
  fputs (" val=", fp);
  switch (node->valuetype)
    {
    case VALTYPE_BOOL:
      fputs (node->value.v_bool? "True":"False", fp);
      break;
    case VALTYPE_CSTR:
      fputs (node->value.v_cstr, fp);
      break;
    case VALTYPE_MEM:
      {
        size_t n;
        unsigned char *p;
        for (p=node->value.v_mem.buf, n=node->value.v_mem.len; n; n--, p++)
          fprintf (fp, "%02X", *p);
      }
      break;
    case VALTYPE_LONG:
      fprintf (fp, "%ld", node->value.v_long);
      break;
    case VALTYPE_ULONG:
      fprintf (fp, "%lu", node->value.v_ulong);
      break;
    default:
      return_if_fail (0);
    }
}

void
_ksba_asn_node_dump (AsnNode p, FILE *fp)
{
  const char *typestr;

  switch (p->type)
    {
    case TYPE_NULL:	    typestr = "NULL"; break;
    case TYPE_CONSTANT:     typestr = "CONST"; break;
    case TYPE_IDENTIFIER:   typestr = "IDENTIFIER"; break;
    case TYPE_INTEGER:	    typestr = "INTEGER"; break;
    case TYPE_ENUMERATED:   typestr = "ENUMERATED"; break;
    case TYPE_UTC_TIME:	    typestr = "UTCTIME"; break;
    case TYPE_GENERALIZED_TIME: typestr = "GENERALIZEDTIME"; break;
    case TYPE_BOOLEAN:	    typestr = "BOOLEAN"; break;
    case TYPE_SEQUENCE:	    typestr = "SEQUENCE"; break;
    case TYPE_BIT_STRING:   typestr = "BIT_STR"; break;
    case TYPE_OCTET_STRING: typestr = "OCT_STR"; break;
    case TYPE_TAG:	    typestr = "TAG"; break;
    case TYPE_DEFAULT:	    typestr = "DEFAULT"; break;
    case TYPE_SIZE:	    typestr = "SIZE"; break;
    case TYPE_SEQUENCE_OF:  typestr = "SEQ_OF"; break;
    case TYPE_OBJECT_ID:    typestr = "OBJ_ID"; break;
    case TYPE_ANY:	    typestr = "ANY"; break;
    case TYPE_SET:          typestr = "SET"; break;
    case TYPE_SET_OF: 	    typestr = "SET_OF"; break;
    case TYPE_CHOICE:	    typestr = "CHOICE"; break;
    case TYPE_DEFINITIONS:  typestr = "DEFINITIONS"; break;
    case TYPE_UTF8_STRING:       typestr = "UTF8_STRING"; break;
    case TYPE_NUMERIC_STRING:    typestr = "NUMERIC_STRING"; break;
    case TYPE_PRINTABLE_STRING:  typestr = "PRINTABLE_STRING"; break;
    case TYPE_TELETEX_STRING:    typestr = "TELETEX_STRING"; break; 
    case TYPE_IA5_STRING:        typestr = "IA5_STRING"; break;
    default:	            typestr = "ERROR\n"; break;
    }

  fprintf (fp, "%s", typestr);
  if (p->name)
    fprintf (fp, " `%s'", p->name);
  print_value (p, fp);
  fputs ("  ", fp);
  switch (p->flags.class)
    { 
    case CLASS_UNIVERSAL:   fputs ("U", fp); break;
    case CLASS_PRIVATE:     fputs ("P", fp); break;
    case CLASS_APPLICATION: fputs ("A", fp); break;
    case CLASS_CONTEXT:     fputs ("C", fp); break;
    }
  
  if (p->flags.explicit)
    fputs (",explicit", fp);
  if (p->flags.implicit)
    fputs (",implicit", fp);
  if (p->flags.is_implicit)
    fputs (",is_implicit", fp);
  if (p->flags.has_tag)
    fputs (",tag", fp);
  if (p->flags.has_default)
    fputs (",default", fp);
  if (p->flags.is_true)
    fputs (",true", fp);
  if (p->flags.is_false)
    fputs (",false", fp);
  if (p->flags.has_list)
    fputs (",list", fp);
  if (p->flags.has_min_max)
    fputs (",min_max", fp);
  if (p->flags.is_optional)
    fputs (",optional", fp);
  if (p->flags.one_param)
    fputs (",1_param", fp);
  if (p->flags.has_size)
    fputs (",size", fp);
  if (p->flags.has_defined_by)
    fputs (",def_by", fp);
  if (p->flags.has_imports)
    fputs (",imports", fp);
  if (p->flags.assignment)
    fputs (",assign",fp);
  if (p->flags.in_set)
    fputs (",in_set",fp);
  if (p->flags.in_choice)
    fputs (",in_choice",fp);
  if (p->flags.in_array)
    fputs (",in_array",fp);
  if (p->flags.not_used)
    fputs (",not_used",fp);
  if (p->flags.skip_this)
    fputs (",[skip]",fp);
  if (p->off != -1 )
    fprintf (fp, " %d.%d.%d", p->off, p->nhdr, p->len );
  
}

void
_ksba_asn_node_dump_all (AsnNode root, FILE *fp)
{
  AsnNode p = root;
  int indent = 0;

  while (p)
    {
      fprintf (fp, "%*s", indent, "");
      _ksba_asn_node_dump (p, fp);
      putc ('\n', fp);

      if (p->down)
	{
	  p = p->down;
	  indent += 2;
	}
      else if (p == root)
	{
	  p = NULL;
	  break;
	}
      else if (p->right)
	p = p->right;
      else
	{
	  while (1)
	    {
	      p = find_up (p);
	      if (p == root)
		{
		  p = NULL;
		  break;
		}
	      indent -= 2;
	      if (p->right)
		{
		  p = p->right;
		  break;
		}
	    }
	}
    }
}

/**
 * ksba_asn_tree_dump:
 * @tree: A Parse Tree
 * @name: Name of the element or NULL
 * @fp: dump to this stream
 *
 * If the first character of the name is a '<' the expanded version of
 * the tree will be printed.
 * 
 * This function is a debugging aid.
 **/
void
ksba_asn_tree_dump (KsbaAsnTree tree, const char *name, FILE *fp)
{
  AsnNode p, root;
  int k, expand=0, indent = 0;

  if (!tree || !tree->parse_tree)
    return;

  if ( name && *name== '<')
    {
      expand = 1;
      name++;
      if (!*name)
        name = NULL;
    }

  root = name? _ksba_asn_find_node (tree->parse_tree, name) : tree->parse_tree;
  if (!root)
    return;

  if (expand)
    root = _ksba_asn_expand_tree (root, NULL);

  p = root;
  while (p)
    {
      for (k = 0; k < indent; k++)
	fprintf (fp, " ");
      _ksba_asn_node_dump (p, fp);
      putc ('\n', fp);

      if (p->down)
	{
	  p = p->down;
	  indent += 2;
	}
      else if (p == root)
	{
	  p = NULL;
	  break;
	}
      else if (p->right)
	p = p->right;
      else
	{
	  while (1)
	    {
	      p = find_up (p);
	      if (p == root)
		{
		  p = NULL;
		  break;
		}
	      indent -= 2;
	      if (p->right)
		{
		  p = p->right;
		  break;
		}
	    }
	}
    }

  /* FIXME: release the tree if expanded */
}

int
ksba_asn_delete_structure (AsnNode root)
{
  AsnNode p, p2, p3;

  if (root == NULL)
    return ASN_ELEMENT_NOT_FOUND;

  p = root;
  while (p)
    {
      if (p->down)
	{
	  p = p->down;
	}
      else
	{			/* no down */
	  p2 = p->right;
	  if (p != root)
	    {
	      p3 = find_up (p);
	      set_down (p3, p2);
	      _ksba_asn_remove_node (p);
	      p = p3;
	    }
	  else
	    {			/* p==root */
	      p3 = _asn1_find_left (p);
	      if (!p3)
		{
		  p3 = find_up (p);
		  if (p3)
		    set_down (p3, p2);
		  else
		    {
		      if (p->right)
			p->right->left = NULL;
		    }
		}
	      else
		set_right (p3, p2);
	      _ksba_asn_remove_node (p);
	      p = NULL;
	    }
	}
    }
  return ASN_OK;
}


AsnNode 
_asn1_copy_structure3 (AsnNode  source_node)
{
  AsnNode dest_node, p_s, p_d, p_d_prev;
  int len;
  enum { DOWN, UP, RIGHT } move;

  if (source_node == NULL)
    return NULL;

  dest_node = add_node (source_node->type);

  p_s = source_node;
  p_d = dest_node;

  move = DOWN;

  do
    {
      if (move != UP)
	{
	  if (p_s->name)
	    _ksba_asn_set_name (p_d, p_s->name);
	  if (p_s->valuetype)
	    {
	      switch (p_s->type)
		{
		case TYPE_OCTET_STRING:
		case TYPE_BIT_STRING:
		case TYPE_INTEGER:
		case TYPE_DEFAULT:
		  len = 0 ;/* FIXME_ksba_asn_get_length_der (p_s->value, &len2);*/
                    /*		  _ksba_asn_set_value (p_d, VALTYPE_MEM, p_s->value., len + len2);*/
		  break;
		default:
		  _ksba_asn_set_value (p_d, VALTYPE_CSTR, p_s->value.v_cstr, 0);
		}
	    }
	  move = DOWN;
	}
      else
	move = RIGHT;

      if (move == DOWN)
	{
	  if (p_s->down)
	    {
	      p_s = p_s->down;
	      p_d_prev = p_d;
	      p_d = add_node (p_s->type);
	      set_down (p_d_prev, p_d);
	    }
	  else
	    move = RIGHT;
	}

      if (p_s == source_node)
	break;

      if (move == RIGHT)
	{
	  if (p_s->right)
	    {
	      p_s = p_s->right;
	      p_d_prev = p_d;
	      p_d = add_node (p_s->type);
	      set_right (p_d_prev, p_d);
	    }
	  else
	    move = UP;
	}
      if (move == UP)
	{
	  p_s = find_up (p_s);
	  p_d = find_up (p_d);
	}
    }
  while (p_s != source_node);

  return dest_node;
}


AsnNode 
_asn1_copy_structure2 (AsnNode  root, char *source_name)
{
  AsnNode source_node;

  source_node = _ksba_asn_find_node (root, source_name);
  return _asn1_copy_structure3 (source_node);
}


int
ksba_asn1_create_structure (AsnNode  root, char *source_name,
                            AsnNode * pointer, char *dest_name)
{
  AsnNode dest_node;
  int res;
  char *end, n[129];

  *pointer = NULL;

  dest_node = _asn1_copy_structure2 (root, source_name);

  if (dest_node == NULL)
    return ASN_ELEMENT_NOT_FOUND;

  _ksba_asn_set_name (dest_node, dest_name);

  end = strchr (source_name, '.');
  if (end)
    {
      memcpy (n, source_name, end - source_name);
      n[end - source_name] = 0;
    }
  else
    {
      strcpy (n, source_name);
    }

  res = expand_identifier (&dest_node, root);
  type_choice_config (dest_node);

  *pointer = dest_node;

  return res;
}


int
_asn1_append_sequence_set (AsnNode  node)
{
  AsnNode p, p2;
  char *temp;
  long n;

  if (!node || !(node->down))
    return ASN_GENERIC_ERROR;

  p = node->down;
  while (p->type == TYPE_TAG || p->type == TYPE_SIZE)
    p = p->right;
  p2 = _asn1_copy_structure3 (p);
  while (p->right)
    p = p->right;
  set_right (p, p2);
  temp = xmalloc (10);
  if (p->name == NULL)
    strcpy (temp, "?1");
  else
    {
      n = strtol (p->name + 1, NULL, 0);
      n++;
      temp[0] = '?';
      _asn1_ltostr (n, temp + 1);
    }
  _ksba_asn_set_name (p2, temp);
  xfree (temp);

  return ASN_OK;
}


int
ksba_asn1_write_value (AsnNode  node_root, char *name, unsigned char *value,
                       int len)
{

  return -1;
#if 0
  AsnNode node, p, p2;
  unsigned char *temp, *value_temp, *default_temp, val[4];
  int len2, k, k2, negative;
  unsigned char *root, *n_end;

  node = _ksba_asn_find_node (node_root, name);
  if (node == NULL)
    return ASN_ELEMENT_NOT_FOUND;

  if (node->flags.is_optional && !value && !len)
    {
      ksba_asn_delete_structure (node);
      return ASN_OK;
    }

  switch (node->type)
    {
    case TYPE_BOOLEAN:
      if (!strcmp (value, "TRUE") || !strcmp (value, "FALSE"))
	{
	  if (node->flags.has_default)
	    {
	      p = node->down;
	      while (p->type == TYPE_DEFAULT) /* XXX ???? */
		p = p->right;
	      if (*value == 'T'? p->flags.is_true: p->flags.is_false)
		_ksba_asn_set_value (node, VALTYPE_NULL, NULL, 0);
	      else
		_ksba_asn_set_value (node, VALTYPE_BOOL,
                                     *value == 'T'? "1":"" , 1);
	    }
	  else
	    _ksba_asn_set_value (node, VALTYPE_BOOL? value,
                                 *value == 'T'? "1":"" , 1);
	}
      else
	return ASN_VALUE_NOT_VALID;
      break;
    case TYPE_INTEGER:
    case TYPE_ENUMERATED:
      if (!len)
	{
	  if (isdigit (value[0]))
	    {
	      value_temp = xmalloc (4);
	      convert_integer (value, value_temp, 4, &len);
	    }
	  else
	    {			/* is an identifier like v1 */
	      if (!(node->flags.has_list))
		return ASN_VALUE_NOT_VALID;
	      p = node->down;
	      while (p)
		{
		  if (p->type == TYPE_CONSTANT)
		    {
		      if (p->name && !strcmp (p->name, value))
			{
			  value_temp = xmalloc (4);
			  convert_integer (p->value, value_temp, 4,
						 &len);
			  break;
			}
		    }
		  p = p->right;
		}
	      if (!p)
		return ASN_VALUE_NOT_VALID;
	    }
	}
      else
	{
	  value_temp = xmalloc (len);
	  memcpy (value_temp, value, len);
	}


      if (value_temp[0] & 0x80)
	negative = 1;
      else
	negative = 0;

      if (negative && node->type == TYPE_ENUMERATED)
	{
	  xfree (value_temp);
	  return ASN_VALUE_NOT_VALID;
	}

      for (k = 0; k < len - 1; k++)
	if (negative && (value_temp[k] != 0xFF))
	  break;
	else if (!negative && value_temp[k])
	  break;

      if ((negative && !(value_temp[k] & 0x80)) ||
	  (!negative && (value_temp[k] & 0x80)))
	k--;

      _asn1_length_der (len - k, NULL, &len2);
      temp = xmalloc (len - k + len2);
      _asn1_octet_der (value_temp + k, len - k, temp, &len2);
      _ksba_asn_set_value (node, VALTYPE_MEM, temp, len2);

      xfree (temp);

      if (node->flags.has_default)
	{
	  p = node->down;
	  while (p->type != TYPE_DEFAULT)
	    p = p->right;
	  if (p->valuetype == VALTYPE_CSTR && isdigit (*p->value.v_cstr))
	    {
	      default_temp = xmalloc (4);
	      convert_integer (p->value.v_cstr, default_temp, 4, &len2);
	    }
	  else
	    {			/* is an identifier like v1 */
	      if (!node->flags.has_list)
		return ASN_VALUE_NOT_VALID;
	      p2 = node->down;
	      while (p2)
		{
		  if (p2->type == TYPE_CONSTANT)
		    {
		      if ((p2->name) 
                          && p->valuetype == VALTYPE_CSTR
                          && !strcmp (p2->name, p->value.v_cstr))
			{
			  default_temp = xmalloc (4);
			  convert_integer (p2->value.v_cstr, default_temp, 4,
						 &len2);
			  break;
			}
		    }
		  p2 = p2->right;
		}
	      if (p2 == NULL)
		return ASN_VALUE_NOT_VALID;
	    }

	  if ((len - k) == len2)
	    {
	      for (k2 = 0; k2 < len2; k2++)
		if (value_temp[k + k2] != default_temp[k2])
		  {
		    break;
		  }
	      if (k2 == len2)
		_ksba_asn_set_value (node, VALTYPE_NULL, NULL, 0);
	    }
	  xfree (default_temp);
	}
      xfree (value_temp);
      break;
    case TYPE_OBJECT_ID:
      for (k = 0; k < strlen (value); k++)
	if ((!isdigit (value[k])) && (value[k] != ' ') && (value[k] != '+'))
	  return ASN_VALUE_NOT_VALID;
      _ksba_asn_set_value (node, VALTYPE_CSTR, value, 0);
      break;
    case TYPE_UTC_TIME:
      if (strlen (value) < 11)
        return ASN_VALUE_NOT_VALID;
      for (k = 0; k < 10; k++)
        if (!isdigit (value[k]))
          return ASN_VALUE_NOT_VALID;
      switch (strlen (value))
        {
        case 11:
          if (value[10] != 'Z')
            return ASN_VALUE_NOT_VALID;
          break;
        case 13:
          if ((!isdigit (value[10])) || (!isdigit (value[11])) ||
              (value[12] != 'Z'))
            return ASN_VALUE_NOT_VALID;
          break;
        case 15:
          if ((value[10] != '+') && (value[10] != '-'))
            return ASN_VALUE_NOT_VALID;
          for (k = 11; k < 15; k++)
            if (!isdigit (value[k]))
              return ASN_VALUE_NOT_VALID;
          break;
        case 17:
          if ((!isdigit (value[10])) || (!isdigit (value[11])))
            return ASN_VALUE_NOT_VALID;
          if ((value[12] != '+') && (value[12] != '-'))
            return ASN_VALUE_NOT_VALID;
          for (k = 13; k < 17; k++)
            if (!isdigit (value[k]))
              return ASN_VALUE_NOT_VALID;
          break;
        default:
          return ASN_VALUE_NOT_FOUND;
        }
      _ksba_asn_set_value (node, VALTYPE_CSTR, value, 0);
      break;
    case TYPE_GENERALIZED_TIME:
      if (value)
        _ksba_asn_set_value (node, VALTYPE_CSTR, value, 0);
      break;
    case TYPE_OCTET_STRING:
      _asn1_length_der (len, NULL, &len2);
      temp = xmalloc (len + len2);
      _asn1_octet_der (value, len, temp, &len2);
      _ksba_asn_set_value (node, VALTYPE_MEM, temp, len2);
      xfree (temp);
      break;
    case TYPE_BIT_STRING:
      _asn1_length_der ((len >> 3) + 2, NULL, &len2);
      temp = xmalloc ((len >> 3) + 2 + len2);
      _asn1_bit_der (value, len, temp, &len2);
      _ksba_asn_set_value (node, VALTYPE_MEM, temp, len2);
      xfree (temp);
      break;
    case TYPE_CHOICE:
      p = node->down;
      while (p)
	{
	  if (!strcmp (p->name, value))
	    {
	      p2 = node->down;
	      while (p2)
		{
		  if (p2 != p)
		    {
		      ksba_asn_delete_structure (p2);
		      p2 = node->down;
		    }
		  else
		    p2 = p2->right;
		}
	      break;
	    }
	  p = p->right;
	}
      if (!p)
	return ASN_ELEMENT_NOT_FOUND;
      break;
    case TYPE_ANY:
      _asn1_length_der (len, NULL, &len2);
      temp = xmalloc (len + len2);
      _asn1_octet_der (value, len, temp, &len2);
      _ksba_asn_set_value (node, VALTYPE_MEM, temp, len2);
      xfree (temp);
      break;
    case TYPE_SEQUENCE_OF:
    case TYPE_SET_OF:
      if (strcmp (value, "NEW"))
	return ASN_VALUE_NOT_VALID;
      _asn1_append_sequence_set (node);
      break;
    default:
      return ASN_ELEMENT_NOT_FOUND;
      break;
    }

  return ASN_OK;
#endif
}

#define PUT_VALUE( ptr, ptr_size, data, data_size) \
	if (ptr_size < data_size) { \
		return ASN_MEM_ERROR; \
	} else { \
		memcpy( ptr, data, data_size); \
		*len = data_size; \
	}

#define PUT_STR_VALUE( ptr, ptr_size, data) \
	if (ptr_size <= strlen(data)) { \
		return ASN_MEM_ERROR; \
	} else { \
		strcpy( ptr, data); \
		*len = strlen(ptr)+1; \
	}

#define ADD_STR_VALUE( ptr, ptr_size, data) \
	if (ptr_size <= strlen(data)+strlen(ptr)) { \
		return ASN_MEM_ERROR; \
	} else { \
		strcat( ptr, data); \
		*len = strlen(ptr)+1; \
	}


int
ksba_asn_read_value (AsnNode root, const char *name,
                     unsigned char *value, int *len)
{
  return -1;
#if 0

  AsnNode node, p;
  int len2, len3;
  int value_size = *len;

  node = _ksba_asn_find_node (root, name);
  if (node == NULL)
    return ASN_ELEMENT_NOT_FOUND;

  if (node->type != TYPE_NULL
      && node->type != TYPE_CHOICE
      && !node->flags.has_default
      && !node->flags.assignment 
      && !node->valuetype)
    return ASN_VALUE_NOT_FOUND;

  switch (node->type)
    {
    case TYPE_NULL:
      PUT_STR_VALUE (value, value_size, "NULL");
      break;
    case TYPE_BOOLEAN:
      if (!node->valuetype && node->flags.has_default)
	{
	  p = node->down;
	  while (p->type != TYPE_DEFAULT)
	    p = p->right;
          assert (p); /* there should be a node of type default below it */
	  if (p->flags.is_true)
	    {
	      PUT_STR_VALUE (value, value_size, "TRUE");
	    }
	  else
	    {
	      PUT_STR_VALUE (value, value_size, "FALSE");
	    }
	}
      else if (node->valuetype == VALTYPE_CSTR
               && *node->value.v_cstr == 'T')
	{
	  PUT_STR_VALUE (value, value_size, "TRUE");
	}
      else
	{
	  PUT_STR_VALUE (value, value_size, "FALSE");
	}
      break;
    case TYPE_INTEGER:
    case TYPE_ENUMERATED:
      if (!node->valuetype && node->flags.has_default)
	{
	  p = node->down;
	  while (p->type != TYPE_DEFAULT)
	    p = p->right;
          assert (p); /* there should be a node of type default below it */
	  if (convert_integer (p->value, value, value_size, len) != ASN_OK)
	    return ASN_MEM_ERROR;
	}
      else if (_asn1_get_octet_der (node->value, &len2, value, value_size, len)
	    != ASN_OK)
	return ASN_MEM_ERROR;
      break;
    case TYPE_OBJECT_ID:
      if (node->flags.assignment)
	{
	  strcpy (value, "");
	  p = node->down;
	  while (p)
	    {
	      if (p->type == TYPE_CONSTANT)
		{
		  ADD_STR_VALUE (value, value_size, p->value);
		  ADD_STR_VALUE (value, value_size, " ");
		}
	      p = p->right;
	    }
	}
      else
	{
	  PUT_STR_VALUE (value, value_size, node->value);
	}
      break;
    case TYPE_UTC_TIME:
    case TYPE_GENERALIZED_TIME:
      PUT_STR_VALUE (value, value_size, node->value);
      break;
    case TYPE_OCTET_STRING:
      if (_asn1_get_octet_der (node->value, &len2, value, value_size, len) !=
	  ASN_OK)
	return ASN_MEM_ERROR;
      break;
    case TYPE_BIT_STRING:
      if (_asn1_get_bit_der (node->value, &len2, value, value_size, len) !=
	  ASN_OK)
	return ASN_MEM_ERROR;
      break;
    case TYPE_CHOICE:
      PUT_STR_VALUE (value, value_size, node->down->name);
      break;
    case TYPE_ANY:
      len2 = _ksba_asn_get_length_der (node->value, &len3);
      PUT_VALUE (value, value_size, node->value + len3, len2);
      break;
    default:
      return ASN_ELEMENT_NOT_FOUND;
      break;
    }
  return ASN_OK;
#endif
}



/* check that all identifiers referenced in the tree are available */
int
_ksba_asn_check_identifier (AsnNode node)
{
  AsnNode p, p2;
  char name2[129];

  if (!node)
    return ASN_ELEMENT_NOT_FOUND;

  for (p = node; p; p = _ksba_asn_walk_tree (node, p))
    {
      if (p->type == TYPE_IDENTIFIER && p->valuetype == VALTYPE_CSTR)
	{
          strcpy (name2, node->name); /* FIXME: check overflow */
          strcat (name2, ".");
	  strcat (name2, p->value.v_cstr);
	  p2 = _ksba_asn_find_node (node, name2);
	  if (!p2)
	    {
	      fprintf (stderr,"reference to `%s' not found\n", name2);
	      return ASN_IDENTIFIER_NOT_FOUND;
	    }
/*            fprintf (stdout,"found reference for `%s' (", name2); */
/*            print_node (p2, stdout); */
/*            fputs (")\n", stdout); */
	}
      else if (p->type == TYPE_OBJECT_ID && p->flags.assignment)
	{ /* an object ID in an assignment */
	  p2 = p->down;
	  if (p2 && (p2->type == TYPE_CONSTANT))
            {  
	      if (p2->valuetype == VALTYPE_CSTR && !isdigit (p2->value.v_cstr[0]))
		{ /* the first constand below is a reference */
                  strcpy (name2, node->name); /* FIXME: check overflow */
                  strcat (name2, ".");
		  strcat (name2, p2->value.v_cstr);
		  p2 = _ksba_asn_find_node (node, name2);
		  if (!p2)
                    {
                      fprintf (stderr,"object id reference `%s' not found\n",
                               name2);
                      return ASN_IDENTIFIER_NOT_FOUND;
                    }
                  else if ( p2->type != TYPE_OBJECT_ID 
                            || !p2->flags.assignment )
		    {
		      fprintf (stderr,"`%s' is not an object id\n", name2);
		      return ASN_IDENTIFIER_NOT_FOUND;
		    }
/*                    fprintf (stdout,"found objid reference for `%s' (", name2); */
/*                    print_node (p2, stdout); */
/*                    fputs (")\n", stdout); */
		}
	    }
	}
    }

  return ASN_OK;
}


/* Get the next node until root is reached in which case NULL is
   returned */
AsnNode
_ksba_asn_walk_tree (AsnNode root, AsnNode node)
{
  if (!node)
    ;
  else if (node->down)
    node = node->down;
  else
    {
      if (node == root)
        node = NULL;
      else if (node->right)
        node = node->right;
      else
        {
          for (;;)
            {
              node = find_up (node);
              if (node == root)
                {
                  node = NULL;
                  break;
                }
              if (node->right)
                {
                  node = node->right;
                  break;
                }
            }
        }
    }

  return node;
}

AsnNode
_ksba_asn_walk_tree_up_right (AsnNode root, AsnNode node)
{
  if (node)
    {
      if (node == root)
        node = NULL;
      else
        {
          for (;;)
            {
              node = find_up (node);
              if (node == root)
                {
                  node = NULL;
                  break;
                }
              if (node->right)
                {
                  node = node->right;
                  break;
                }
            }
        }
    }

  return node;
}

/* walk over the tree and change the value type of all integer types
   from string to long. */
int
_ksba_asn_change_integer_value (AsnNode node)
{
  AsnNode p;

  if (node == NULL)
    return ASN_ELEMENT_NOT_FOUND;

  for (p = node; p; p = _ksba_asn_walk_tree (node, p))
    {
      if (p->type == TYPE_INTEGER && p->flags.assignment)
	{
	  if (p->valuetype == VALTYPE_CSTR)
	    {
              long val = strtol (p->value.v_cstr, NULL, 10);
	      _ksba_asn_set_value (p, VALTYPE_LONG, &val, sizeof(val));
	    }
	}
    }

  return ASN_OK;
}


int
_ksba_asn_delete_not_used (AsnNode  node)
{
  AsnNode p, p2;

  if (node == NULL)
    return ASN_ELEMENT_NOT_FOUND;

  for (p = node; p; p = _ksba_asn_walk_tree (node, p) )
    {
      if (p->flags.not_used)
	{
	  p2 = NULL;
	  if (p != node)
	    {
	      p2 = _asn1_find_left (p);
	      if (!p2)
		p2 = find_up (p);
	    }
	  ksba_asn_delete_structure (p);
	  p = p2;
	}
    }

  return ASN_OK;
}



static int
expand_identifier (AsnNode * node, AsnNode root)
{
  if (node == NULL)
    return ASN_ELEMENT_NOT_FOUND;
#warning fix this
  return ASN_OK;
#if 0
  AsnNode p, p2, p3;
  char name2[129];
  for (p = node; p; p = _ksba_asn_walk_tree (node, p))
    {
      if (p->type == TYPE_IDENTIFIER && p->valuetype == VALTYPE_CSTR)
        {
          strcpy (name2, root->name);
          strcat (name2, ".");
          strcat (name2, p->value.v_cstr);
          p2 = _asn1_copy_structure2 (root, name2);
          assert (p2);
          if (p2 == NULL)
            return ASN_IDENTIFIER_NOT_FOUND;
          _ksba_asn_set_name (p2, p->name);
          p2->right = p->right;
          p2->left = p->left;
          if (p->right)
            p->right->left = p2;
          p3 = p->down;
          if (p3)
            {
              while (p3->right)
                p3 = p3->right;
              set_right (p3, p2->down);
              set_down (p2, p->down);
            }
          
          p3 = _asn1_find_left (p);
          if (p3)
            set_right (p3, p2);
          else
            {
              p3 = find_up (p);
              if (p3)
                set_down (p3, p2);
              else
                {
                  p2->left = NULL;
                }
            }
          
          if (p->flags.has_size)
            p2->flags.has_size = 1;
          if (p->flags.has_tag)
            p2->flags.has_tag = 1;
          if (p->flags.is_optional)
            p2->flags.is_optional = 1;
          if (p->flags.has_default)
            p2->flags.has_default = 1;
          if (p->flags.in_set)
            p2->flags.in_set = 1;;
          if (p->flags.in_choice)
            p2->flags.in_choice = 1;;
          if (p->flags.in_array)
            p2->flags.in_array = 1;;
          if (p->flags.not_used)
            p2->flags.not_used = 1;
          
          if (p == *node)
            *node = p2;
          _ksba_asn_remove_node (p);
          p = p2;
        }
    }
#endif
}



static int
type_choice_config (AsnNode node)
{
  AsnNode p, p2, p3, p4;

  if (!node)
    return KSBA_Element_Not_Found;

 restart:
  for (p = node; p; p = _ksba_asn_walk_tree (node, p))
    {
      if (p->type == TYPE_CHOICE && p->flags.has_tag)
        {
          for (p2 = p->down; p2; p2 = p2->right)
            {
              if (p2->type != TYPE_TAG)
                {
                  p2->flags.has_tag = 1;
                  for (p3 = _asn1_find_left (p2);
                       p3; p3 = _asn1_find_left (p3))
                    {
                      if (p3->type == TYPE_TAG)
                        {
                          p4 = add_node (TYPE_TAG);
                          p4->flags = p3->flags;
                          copy_value (p4, p3);
                          set_right (p4, p2->down);
                          set_down (p2, p4);
                        }
                    }
                }
            }

          p->flags.has_tag = 0;
          p2 = p->down;
          while (p2)
            {
              p3 = p2->right;
              if (p2->type == TYPE_TAG)
                ksba_asn_delete_structure (p2);
              p2 = p3;
            }
          goto restart;
        }
    }

  return 0;
}


/* Expand all object ID constants */
int
_ksba_asn_expand_object_id (AsnNode node)
{
  AsnNode p, p2, p3, p4, p5;
  char name_root[129], name2[129*2+1];

  /* FIXME: Make a cleaner implementation */
  if (!node)
    return KSBA_Element_Not_Found;
  if (!node->name)
    return KSBA_Invalid_Value;
  if (strlen(node->name) >= DIM(name_root)-1)
    return KSBA_General_Error;
  strcpy (name_root, node->name);

 restart:
  for (p = node; p; p = _ksba_asn_walk_tree (node, p))
    {
      if (p->type == TYPE_OBJECT_ID && p->flags.assignment)
        {
          p2 = p->down;
          if (p2 && p2->type == TYPE_CONSTANT)
            {
              if (p2->valuetype == VALTYPE_CSTR
                  && !isdigit (p2->value.v_cstr[0]))
                {
                  if (strlen(p2->value.v_cstr)+1+strlen(name2) >= DIM(name2)-1)
                    return KSBA_General_Error;
                  strcpy (name2, name_root);
                  strcat (name2, ".");
                  strcat (name2, p2->value.v_cstr);
                  p3 = _ksba_asn_find_node (node, name2);
                  if (!p3 || p3->type != TYPE_OBJECT_ID ||
                      !p3->flags.assignment)
                    return ASN_ELEMENT_NOT_FOUND;
                  set_down (p, p2->right);
                  _ksba_asn_remove_node (p2);
                  p2 = p;
                  p4 = p3->down;
                  while (p4)
                    {
                      if (p4->type == TYPE_CONSTANT)
                        {
                          p5 = add_node (TYPE_CONSTANT);
                          _ksba_asn_set_name (p5, p4->name);
                          _ksba_asn_set_value (p5, VALTYPE_CSTR,
                                               p4->value.v_cstr, 0);
                          if (p2 == p)
                            {
                              set_right (p5, p->down);
                              set_down (p, p5);
                            }
                          else
                            {
                              set_right (p5, p2->right);
                              set_right (p2, p5);
                            }
                          p2 = p5;
                        }
                      p4 = p4->right;
                    }
                  goto restart;  /* the most simple way to get it right ;-) */
                }
            }
        }
    }
  return 0;
}

/* Walk the parse tree and set the default tag where appropriate.  The
   node must be of type DEFINITIONS */
void
_ksba_asn_set_default_tag (AsnNode node)
{
  AsnNode p;

  return_if_fail (node && node->type == TYPE_DEFINITIONS);

  for (p = node; p; p = _ksba_asn_walk_tree (node, p))
    {
      if ( p->type == TYPE_TAG
           && !p->flags.explicit && !p->flags.implicit)
	{
	  if (node->flags.explicit)
	    p->flags.explicit = 1;
	  else
	    p->flags.implicit = 1;
	}
    }
  /* now mark the nodes which are implicit */
  for (p = node; p; p = _ksba_asn_walk_tree (node, p))
    {
      if ( p->type == TYPE_TAG && p->flags.implicit && p->down)
	{
	  if (p->down->type == TYPE_CHOICE)
            ; /* a CHOICE is per se implicit */
	  else if (p->down->type != TYPE_TAG)
	    p->down->flags.is_implicit = 1;
	}
    }
}

/* Walk the tree and set the is_set and not_used flags for all nodes below
   a node of type SET. */
void
_ksba_asn_type_set_config (AsnNode node)
{
  AsnNode p, p2;

  return_if_fail (node && node->type == TYPE_DEFINITIONS);

  for (p = node; p; p = _ksba_asn_walk_tree (node, p))
    {
      if (p->type == TYPE_SET)
        {
          for (p2 = p->down; p2; p2 = p2->right)
            {
              if (p2->type != TYPE_TAG)
                {
                  p2->flags.in_set = 1;
                  p2->flags.not_used = 1;
                }
            }
        }
      else if (p->type == TYPE_CHOICE)
        {
          for (p2 = p->down; p2; p2 = p2->right)
            {
                p2->flags.in_choice = 1;
            }
        }
      else if (p->type == TYPE_SEQUENCE_OF || p->type == TYPE_SET_OF)
        {
          for (p2 = p->down; p2; p2 = p2->right)
            p2->flags.in_array = 1;
        }
    }
}

/* Create a copy the tree at SRC_ROOT. s is a helper which should be
   set to SRC_ROOT by the caller */
static AsnNode
copy_tree (AsnNode src_root, AsnNode s)
{
  AsnNode first=NULL, dprev=NULL, d, down, tmp;

  for (; s; s=s->right )
    {
      down = s->down;
      d = copy_node (s);

      if (!first)
        first = d;
      else
        {
          dprev->right = d;
          d->left = dprev;
        }
      dprev = d;
      if (down)
        {
          tmp = copy_tree (src_root, down);
          if (d->down && tmp)
            { /* Need to merge it with the existing down */
              AsnNode x;

              for (x=d->down; x->right; x = x->right)
                ;
              x->right = tmp;
              tmp->left = x;
            }
          else 
            {
              d->down = tmp;
              if (d->down)
                d->down->left = d;
            }
        }
    }
  return first;
}



static AsnNode
resolve_identifier (AsnNode root, AsnNode node, int nestlevel)
{
  char *buf;
  AsnNode n;

  if (nestlevel > 20)
    return NULL;

  return_null_if_fail (root);
  return_null_if_fail (node->valuetype == VALTYPE_CSTR);

  buf = alloca (strlen(root->name)+strlen(node->value.v_cstr)+2);
  return_null_if_fail (buf);
  strcpy (stpcpy (stpcpy (buf, root->name), "."), node->value.v_cstr);
  n = _ksba_asn_find_node (root, buf);
  /* we do just a simple indirection */
  if (n && n->type == TYPE_IDENTIFIER)
    n = resolve_identifier (root, n, nestlevel+1);
  return n;
}


static AsnNode
do_expand_tree (AsnNode src_root, AsnNode s, int depth)
{
  AsnNode first=NULL, dprev=NULL, d, down, tmp;

  /* On the very first level we do not follow the right pointer so that
     we can break out a valid subtree. */
  for (; s; s=depth?s->right:NULL )
    {
      down = s->down;
      if (s->type == TYPE_IDENTIFIER)
        {
          AsnNode s2, *dp;

          d = resolve_identifier (src_root, s, 0);
          if (!d)
            {
              fprintf (stderr, "RESOLVING IDENTIFIER FAILED\n");
              continue;
            }
          down = d->down;
          d = copy_node (d);
          if (s->flags.is_optional)
            d->flags.is_optional = 1;
          if (s->flags.in_choice)
            d->flags.in_choice = 1;
          if (s->flags.in_array)
            d->flags.in_array = 1;
          if (s->flags.is_implicit)
            d->flags.is_implicit = 1;
          /* we don't want the resolved name - change it back */
          _ksba_asn_set_name (d, s->name);
          /* copy the default and tag attributes */
          tmp = NULL;
          dp = &tmp;
          for (s2=s->down; s2; s2=s2->right)
            {
              AsnNode x;

              x = copy_node (s2);
              x->left = *dp? *dp : d;
              *dp = x;
              dp = &(*dp)->right;

              if (x->type == TYPE_TAG)
                d->flags.has_tag =1;
              else if (x->type == TYPE_DEFAULT)
                d->flags.has_default =1;
            }
          d->down = tmp;
        }
      else
        d = copy_node (s);

      if (!first)
        first = d;
      else
        {
          dprev->right = d;
          d->left = dprev;
        }
      dprev = d;
      if (down)
        {
          if (depth >= 1000)
            {
              fprintf (stderr, "ASN.1 TREE TOO TALL!\n");
              tmp = NULL;
            }
          else
            tmp = do_expand_tree (src_root, down, depth+1);
          if (d->down && tmp)
            { /* Need to merge it with the existing down */
              AsnNode x;

              for (x=d->down; x->right; x = x->right)
                ;
              x->right = tmp;
              tmp->left = x;
            }
          else 
            {
              d->down = tmp;
              if (d->down)
                d->down->left = d;
            }
        }
    }
  return first;
}

  
/* Expand the syntax tree so that all references are resolved and we
   are able to store values right in the tree (except for set/sequence
   of).  This expanded tree is also an requirement for doing the DER
   decoding as the resolving of identifiers leads to a lot of
   problems.  We use more memory of course, but this is negligible
   because the entire code wioll be simpler and faster */
AsnNode
_ksba_asn_expand_tree (AsnNode parse_tree, const char *name)
{
  AsnNode root;

  root = name? _ksba_asn_find_node (parse_tree, name) : parse_tree;
  return do_expand_tree (parse_tree, root, 0);
}


/* Insert a copy of the entire tree at NODE as the sibling of itself
   and return the copy */
AsnNode
_ksba_asn_insert_copy (AsnNode node)
{
  AsnNode n;

  n = copy_tree (node, node);
  if (!n)
    return NULL; /* out of core */
  return_null_if_fail (n->right == node->right);
  node->right = n;
  n->left = node;
  
  return n;
}


/* Locate a type value sequence like

  SEQUENCE { 
     type    OBJECT IDENTIFIER
     value   ANY
  }

  below root and return the 'value' node.  OIDBUF should contain the
  DER encoding of an OID value.  idx is the number of OIDs to skip;
  this can be used to enumerate structures with the same OID */
AsnNode
_ksba_asn_find_type_value (const unsigned char *image, AsnNode root, int idx,
                           const void *oidbuf, size_t oidlen)
{
  AsnNode n, noid;

  if (!image || !root)
    return NULL;

  for (n = root; n; n = _ksba_asn_walk_tree (root, n) )
    {
      if ( n->type == TYPE_SEQUENCE
           && n->down && n->down->type == TYPE_OBJECT_ID)
        {
          noid = n->down;
          if (noid->off != -1 && noid->len == oidlen
              && !memcmp (image + noid->off + noid->nhdr, oidbuf, oidlen)
              && noid->right)
            {
              if ( !idx-- )
                return noid->right;
            }
          
        }
    }
  return NULL;
}





