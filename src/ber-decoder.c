/* ber-decoder.c - Basic Encoding Rules Decoder
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "util.h"

#include "ksba.h"
#include "asn1-func.h"
#include "ber-decoder.h"

struct ber_decoder_s {
  AsnNode module;    /* the ASN.1 structure */
  KsbaReader reader;
  const char *last_errdesc; /* string with the error description */
  int non_der; /* set if the encoding is not DER conform */
};


static int
set_error (BerDecoder d, AsnNode node, const char *text)
{
  fprintf (stderr,"ber-decoder: node `%s': %s\n", 
           node? node->name:"?", text);
  d->last_errdesc = text;
  return KSBA_BER_Error;
}


static int
eof_or_error (BerDecoder d, int premature)
{
  if (ksba_reader_error (d->reader))
    {
      set_error (d, NULL, "read error");
      return KSBA_Read_Error;
    }
  if (premature)
    return set_error (d, NULL, "premature EOF");
  return -1;
}

static const char *
universal_tag_name (unsigned long no)
{
  static const char *names[31] = {
    "[End Tag]",
    "BOOLEAN",
    "INTEGER",
    "BIT STRING",
    "OCTECT STRING",
    "NULL",
    "OBJECT IDENTIFIER",
    "ObjectDescriptor",
    "EXTERNAL",
    "REAL",
    "ENUMERATED",
    "EMBEDDED PDV",
    "UTF8String",
    "RELATIVE-OID",
    "[UNIVERSAL 14]",
    "[UNIVERSAL 15]",
    "SEQUENCE",
    "SET",
    "NumericString",
    "PrintableString",
    "TeletexString",
    "VideotexString",
    "IA5String",
    "UTCTime",
    "GeneralizedTime",
    "GraphicString",
    "VisibleString",
    "GeneralString",
    "UniversalString",
    "CHARACTER STRING",
    "BMPString"
  };

  return no < DIM(names)? names[no]:NULL;
}








BerDecoder
_ksba_ber_decoder_new (void)
{
  BerDecoder d;

  d = xtrycalloc (1, sizeof *d);
  if (!d)
    return NULL;

  return d;
}

void
_ksba_ber_decoder_release (BerDecoder d)
{
  xfree (d);
}

/**
 * _ksba_ber_decoder_set_module:
 * @d: Decoder object 
 * @module: ASN.1 Parse tree
 * 
 * Initialize the decoder with the ASN.1 module.  Note, that this is a
 * shallow copy of the module.  FIXME: What about ref-counting of
 * AsnNodes?
 * 
 * Return value: 0 on success or an error code
 **/
KsbaError
_ksba_ber_decoder_set_module (BerDecoder d, KsbaAsnTree module)
{
  if (!d || !module)
    return KSBA_Invalid_Value;
  if (d->module)
    return KSBA_Conflict; /* module already set */

  d->module = module->parse_tree;
  return 0;
}


KsbaError
_ksba_ber_decoder_set_reader (BerDecoder d, KsbaReader r)
{
  if (!d || !r)
    return KSBA_Invalid_Value;
  if (d->reader)
    return KSBA_Conflict; /* reader already set */
  
  d->reader = r;
  return 0;
}


/**********************************************
 ***********  decoding machinery  *************
 **********************************************/

struct tag_info {
  enum tag_class class;
  int is_constructed;
  unsigned long tag;
};


static int
read_byte (KsbaReader reader)
{
  unsigned char buf;
  size_t nread;
  int rc;

  do
    rc = ksba_reader_read (reader, &buf, 1, &nread);
  while (!rc && !nread);
  return rc? -1: buf;
}

/*
 * Read the tag and the length part from the TLV triplet. 
 */
static KsbaError
read_tl (BerDecoder d, struct tag_info *r_tag, 
         unsigned long *r_length, int *r_indefinite, size_t *r_nread)
{
  int c;
  unsigned long tag;

  *r_length = 0;
  *r_indefinite = 0;
  *r_nread = 0;
  /* Get the tag */
  c = read_byte (d->reader);
  if (c==-1)
    return eof_or_error (d, 0);
  ++*r_nread;
  r_tag->class = (c & 0xc0) >> 6;
  r_tag->is_constructed = !!(c & 0x20);
  tag = c & 0x1f;
  if (tag == 0x1f)
    {
      tag = 0;
      do
        {
          /* fixme: check for overflow of out datatype */
          tag <<= 7;
          c = read_byte (d->reader);
          if (c == -1)
            return eof_or_error (d, 1);
          ++*r_nread;
          tag |= c & 0x7f;
        }
      while (c & 0x80);
    }
  r_tag->tag = tag;

  /* Get the length */
  c = read_byte (d->reader);
  if (c == -1)
    return eof_or_error (d, 1);
  ++*r_nread;
  if ( !(c & 0x80) )
    *r_length = c;
  else if (c == 0x80)
    {
      *r_indefinite = 1;
      d->non_der = 1;
    }
  else if (c == 0xff)
      return set_error (d, NULL, "forbidden length value");
  else
    {
      unsigned long len = 0;
      int count = c & 0x7f;

      /* fixme: check for overflow of our length type */
      for (; count; count--)
        {
          len <<= 8;
          c = read_byte (d->reader);
          if (c == -1)
            return eof_or_error (d, 1);
          ++*r_nread;
          len |= c & 0xff;
        }
      *r_length = len;
    }

  return 0;
}


static int
cmp_tag (AsnNode node, const struct tag_info *ti)
{
  return ti->tag == node->type && ti->class == node->flags.class;
}


/* Find the matching node for the tag described by ti.  ROOT is the
   root node of the syntaxtree, node either NULL or the last node
   matched.  */
static AsnNode
find_node (AsnNode root, AsnNode node, const struct tag_info *ti)
{
  if (!node)
    node = root;

  while (node)
    {
      if (cmp_tag (node, ti))
        {
          return node; /* found */
        }

      if (node->down)
        node = node->down;
      else if (node == root)
        return NULL; /* not found */
      else if (node->right)
        node = node->right;
      else 
        { /* go up and right */
          do
            {
              while (node->left && node->left->right == node)
                node = node->left;
              node = node->left;
              
              if (!node || node == root)
                return NULL; /* back at the root -> not found */
            }
          while (!node->right);
          node = node->right;
        }
    }

  return NULL;
}


KsbaError
_ksba_ber_decoder_decode (BerDecoder d)
{
  
  
  return -1;
}

/**
 * _ksba_ber_decoder_dump:
 * @d: Decoder object
 * 
 * Dump a textual representation of the encoding to the given stream.
 * 
 * Return value: 
 **/
KsbaError
_ksba_ber_decoder_dump (BerDecoder d, FILE *fp)
{
  struct tag_info ti;
  int rc;
  unsigned long length, tlvlen;
  int is_indefinite;
  int depth = 0;
  size_t nread;
  struct {
    unsigned long nleft;
    unsigned long length;
    int ndef;
  } stack[100];
  AsnNode rootnode, curnode, node;
  enum {
    DS_INIT, DS_BYPASS, DS_NEXT
  } state = DS_INIT;
    


  rootnode = d->module;
  curnode = NULL;
  while ( !(rc = read_tl (d, &ti, &length, &is_indefinite, &nread)) )
    {
      const char *tagname = NULL;

      /* Without this kludge some example certs can't be parsed */
      if (ti.class == CLASS_UNIVERSAL && !ti.tag)
        length = 0;

      tlvlen = length + nread;
      if (ti.class == CLASS_UNIVERSAL)
        tagname = universal_tag_name (ti.tag);

      fprintf (fp, "%*s", depth*2, "");
      if (tagname)
        fputs (tagname, fp);
      else
        fprintf (fp, "[%s %lu]", 
                 ti.class == CLASS_UNIVERSAL? "UNIVERSAL" :
                 ti.class == CLASS_APPLICATION? "APPLICATION" :
                 ti.class == CLASS_CONTEXT? "CONTEXT-SPECIFIC" : "PRIVATE",
                 ti.tag);
      fprintf (fp, " %c n=%u", ti.is_constructed? 'c':'p', nread);
      if (is_indefinite)
        fputs (" indefinite length ", fp);
      else
        fprintf (fp, " %lu octets ", length);

      if (state != DS_BYPASS)
        {
          node = find_node (rootnode, curnode, &ti);
          switch (state)
            {
            case DS_INIT:
              if (!node)
                {
                  state = DS_BYPASS;
                  fputs (" anchor node not found", fp);
                  break;
                }
              /* fall thru */
            default:
              if (node)
                {
                  putc ('(', fp);
                  _ksba_asn_node_dump (node, fp);
                  putc (')', fp);
                  curnode = node;
                }
              state = DS_NEXT;
              break;
            } 
          
        }
      putc ('\n', fp);
      
      if (!ti.is_constructed)
        { /* primitive: skip value */
          int n;

          for (n=0; n < length; n++)
            if (read_byte (d->reader) == -1)
              return eof_or_error (d, 1);
        }

      if (depth && !ti.is_constructed)
        {
          if (stack[depth-1].ndef)
            {
              if (ti.class == CLASS_UNIVERSAL && !ti.tag && !length)
                depth--;
            }
          else
            {
              if (tlvlen > stack[depth-1].nleft)
                {
                  fprintf (fp, "error: "
                           "object length field %lu octects too large\n",
                           (tlvlen - stack[depth-1].nleft) );
                  stack[depth-1].nleft = 0;
                }
              else
                stack[depth-1].nleft -= tlvlen;
/*                fprintf (fp, "depth %d %lu bytes of %lu left\n", */
/*                         depth, stack[depth-1].nleft, stack[depth-1].length); */
              if (depth && !stack[depth-1].nleft)
                  depth--;
            }
        }

      if (ti.is_constructed)
        {  /* constructed */
          if (depth == DIM(stack))
            {
              fprintf (fp, "error: objects nested too deep\n");
              rc = KSBA_General_Error;
              break;
            }
          stack[depth].nleft  = length; 
          stack[depth].length = length;
          stack[depth].ndef = is_indefinite;
          depth++;
        }
    }

  if (rc==-1 && !d->last_errdesc)
    rc = 0;

  return rc;
}



