/* der-decoder.c - Distinguished Encoding Rules Encoder
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
#include "ber-help.h"
#include "der-encoder.h"


struct der_encoder_s {
  AsnNode module;    /* the ASN.1 structure */
  KsbaWriter writer;
  const char *last_errdesc; /* string with the error description */
  AsnNode root;   /* of the expanded parse tree */
  int debug;
};

#if 0
static int
set_error (DerEncoder d, AsnNode node, const char *text)
{
  fprintf (stderr,"der-encoder: node `%s': %s\n", 
           node? node->name:"?", text);
  d->last_errdesc = text;
  return KSBA_Encoding_Error;
}
#endif

/* To be useful for the DER encoder we store all data direct as the
   binary image, so we use the VALTYPE_MEM */
static KsbaError
store_value (AsnNode node, const void *buffer, size_t length)
{
  _ksba_asn_set_value (node, VALTYPE_MEM, buffer, length);
  return 0;
}

static void
clear_value (AsnNode node)
{
  _ksba_asn_set_value (node, VALTYPE_NULL, NULL, 0);
}




DerEncoder
_ksba_der_encoder_new (void)
{
  DerEncoder d;

  d = xtrycalloc (1, sizeof *d);
  if (!d)
    return NULL;

  return d;
}

void
_ksba_der_encoder_release (DerEncoder d)
{
  xfree (d);
}


/**
 * _ksba_der_encoder_set_module:
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
_ksba_der_encoder_set_module (DerEncoder d, KsbaAsnTree module)
{
  if (!d || !module)
    return KSBA_Invalid_Value;
  if (d->module)
    return KSBA_Conflict; /* module already set */

  d->module = module->parse_tree;
  return 0;
}


KsbaError
_ksba_der_encoder_set_writer (DerEncoder d, KsbaWriter w)
{
  if (!d || !w)
    return KSBA_Invalid_Value;
  if (d->writer)
    return KSBA_Conflict; /* reader already set */
  
  d->writer = w;
  return 0;
}


/**********************************************
 ***********  encoding machinery  *************
 **********************************************/
#if 0
static int
write_byte (KsbaWriter writer, int c)
{
  unsigned char buf;

  buf = c;
  return ksba_writer_write (writer, &buf, 1);
}

/* read COUNT bytes into buffer.  buffer may be NULL to skip over
   COUNT bytes.  Return 0 on success */
static int 
read_buffer (KsbaReader reader, char *buffer, size_t count)
{
  size_t nread;

  if (buffer)
    {
      while (count)
        {
          if (ksba_reader_read (reader, buffer, count, &nread))
            return -1;
          buffer += nread;
          count -= nread;
        }
    }
  else
    {
      char dummy[256];
      size_t n;

      while (count)
        {
          n = count > DIM(dummy) ? DIM(dummy): count;
          if (ksba_reader_read (reader, dummy, n, &nread))
            return -1;
          count -= nread;
        }
    }
  return 0;
}

/* Return 0 for no match, 1 for a match and 2 for an ANY match of an
   constructed type */
static int
cmp_tag (AsnNode node, const struct tag_info *ti)
{
  if (node->flags.class != ti->class)
    return 0;
  if (node->type == TYPE_TAG)
    {
      return_val_if_fail (node->valuetype == VALTYPE_ULONG, 0);
      return node->value.v_ulong == ti->tag;
    }
  if (node->type == ti->tag)
    return 1;
  if (ti->class == CLASS_UNIVERSAL)
    {
      if (node->type == TYPE_SEQUENCE_OF && ti->tag == TYPE_SEQUENCE)
        return 1;
      if (node->type == TYPE_SET_OF && ti->tag == TYPE_SET)
        return 1;
      if (node->type == TYPE_ANY)
        return is_primitive_type (ti->tag)? 1:2; 
    }

  return 0;
}

/* Find the node in the tree ROOT corresponding to TI and return that
   node.  Returns NULL if the node was not found */
static AsnNode
find_anchor_node (AsnNode root, const struct tag_info *ti)
{
  AsnNode node = root;

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

static int
match_der (AsnNode root, const struct tag_info *ti,
           DECODER_STATE ds, AsnNode *retnode, int debug)
{
  int rc;
  AsnNode node;

  *retnode = NULL;
  node = ds->cur.node;
  if (!node)
    {
      if (debug)
        puts ("  looking for anchor");
      node = find_anchor_node (root,  ti);
      if (!node)
        fputs (" anchor node not found\n", stdout);
    }
  else if (ds->cur.again)
    {
      if (debug)
        puts ("  doing last again");
      ds->cur.again = 0;
    }
  else if (is_primitive_type (node->type) || node->type == TYPE_ANY
           || node->type == TYPE_SIZE || node->type == TYPE_DEFAULT )
    {
      if (debug)
        puts ("  primitive type - get next");
      if (node->right)
        node = node->right;
      else if (!node->flags.in_choice)
        node = NULL;
      else /* in choice */
        {
          if (debug)
            puts ("  going up after choice - get next");
          while (node->left && node->left->right == node)
            node = node->left;
          node = node->left; /* this is the up pointer */
          if (node)
            node = node->right;
        }
    }
  else if (node->type == TYPE_SEQUENCE_OF || node->type == TYPE_SET_OF)
    {
      if (debug)
        {
          printf ("  prepare for seq/set_of (%d %d)  ",
                  ds->cur.length, ds->cur.nread);
          printf ("  cur: ("); _ksba_asn_node_dump (node, stdout);
          printf (")\n");
          if (ds->cur.node->flags.in_array)
            puts ("  This is in an arrat!");
          if (ds->cur.went_up)
            puts ("  And we going up!");
        }
      if ((ds->cur.went_up && !ds->cur.node->flags.in_array) ||
          (ds->idx && ds->cur.nread >= ds->stack[ds->idx-1].length))
        {
          if (debug)
            printf ("  advancing\n");
          if (node->right)
            node = node->right;
          else
            {
              for (;;)
                {
                  while (node->left && node->left->right == node)
                    node = node->left;
                  node = node->left; /* this is the up pointer */
                  if (!node)
                    break;
                  if (node->right)
                    {
                      node = node->right;
                      break;
                    }
                }
            }
        }
      else if (ds->cur.node->flags.in_array
               && ds->cur.went_up)
        {
          if (debug)
            puts ("  Reiterating");
          node = _ksba_asn_insert_copy (node);
          if (node)
            prepare_copied_tree (node);
        }
      else
        node = node->down;
    }
  else /* constructed */
    {
      if (debug)
        {
          printf ("  prepare for constructed (%d %d) ",
                  ds->cur.length, ds->cur.nread);
          printf ("  cur: ("); _ksba_asn_node_dump (node, stdout);
          printf (")\n");
          if (ds->cur.node->flags.in_array)
            puts ("  This is in an array!");
          if (ds->cur.went_up)
            puts ("  And we going up!");
        }
      ds->cur.in_seq_of = 0;

      if (ds->cur.node->flags.in_array
          && ds->cur.went_up)
        {
          if (debug)
            puts ("  Reiterating this");
          node = _ksba_asn_insert_copy (node);
          if (node)
            prepare_copied_tree (node);
        }
      else if (ds->cur.went_up || ds->cur.next_tag || ds->cur.node->flags.skip_this)
        {
          if (node->right)
            node = node->right;
          else
            {
              for (;;)
                {
                  while (node->left && node->left->right == node)
                    node = node->left;
                  node = node->left; /* this is the up pointer */
                  if (!node)
                    break;
                  if (node->right)
                    {
                      node = node->right;
                      break;
                    }
                }
            }
        }
      else 
        node = node->down;
      
    }
  if (!node)
    return -1;
  ds->cur.node = node;
  ds->cur.went_up = 0;
  ds->cur.next_tag = 0;

  if (debug)
    {
      printf ("  Expect ("); _ksba_asn_node_dump (node, stdout); printf (")\n");
    }

  if (node->flags.skip_this)
    return 1;

  if (node->type == TYPE_SIZE)
    {
      if (debug)
        printf ("   skipping size tag\n");
      return 1;
    }
  if (node->type == TYPE_DEFAULT)
    {
      if (debug)
        printf ("   skipping default tag\n");
      return 1;
    }

  if (node->flags.is_implicit)
    {
      if (debug)
        printf ("   dummy accept for implicit tag\n");
      return 1; /* again */
    }

  if ( (rc=cmp_tag (node, ti)))
    {
      *retnode = node;
      return rc==2? 4:3;
    }
    
  if (node->type == TYPE_CHOICE)
    {
      if (debug)
        printf ("   testing choice...\n");
      for (node = node->down; node; node = node->right)
        {
          if (debug)
            {
              printf ("       %s (", node->flags.skip_this? "skip":" cmp");
              _ksba_asn_node_dump (node, stdout);
              printf (")\n");
            }

          if (!node->flags.skip_this && cmp_tag (node, ti) == 1)
            {
              if (debug)
                {
                  printf ("  choice match <"); dump_tlv (ti, stdout);
                  printf (">\n");
                }
              /* mark the remaining as done */
              for (node=node->right; node; node = node->right)
                  node->flags.skip_this = 1;
              return 1;
            }
          node->flags.skip_this = 1;

        }
      node = ds->cur.node; /* reset */
    }

  if (node->flags.in_choice)
    {
      if (debug)
        printf ("   skipping non matching choice\n");
      return 1;
    }
  
  if (node->flags.is_optional)
    {
      if (debug)
        printf ("   skipping optional element\n");
      if (node->type == TYPE_TAG)
        ds->cur.next_tag = 1;
      return 1;
    }

  if (node->flags.has_default)
    {
      if (debug)
        printf ("   use default value\n");
      if (node->type == TYPE_TAG)
        ds->cur.next_tag = 1;
      *retnode = node;
      return 2;
    }

  return -1;
}


static KsbaError 
decoder_init (DerEncoder d, const char *start_name)
{
  d->ds = new_decoder_state ();

  d->root = _ksba_asn_expand_tree (d->module, start_name);
  clear_help_flags (d->root);
  d->bypass = 0;
  if (d->debug)
    printf ("DECODER_INIT for `%s'\n", start_name? start_name: "[root]");
  return 0;
}

static void
decoder_deinit (DerEncoder d)
{
  release_decoder_state (d->ds);
  d->ds = NULL;
  d->val.node = NULL;
  if (d->debug)
    printf ("DECODER_DEINIT\n");
}


static KsbaError
decoder_next (DerEncoder d)
{
  struct tag_info ti;
  AsnNode node;
  KsbaError err;
  DECODER_STATE ds = d->ds;
  int debug = d->debug;

  err = _ksba_ber_read_tl (d->reader, &ti);
  if (err)
    {
      return err;
    }

  if (debug)
    {
      printf ("ReadTLV <"); dump_tlv (&ti, stdout); printf (">\n");
    }

  if (d->use_image)
    {
      if (!d->image.buf)
        {
          /* we need some extra bytes to store the stuff we read ahead
             at the end of the module which is later pushed back */
          d->image.length = ti.length + 100;
          d->image.used = 0;
          d->image.buf = xtrymalloc (d->image.length);
          if (!d->image.buf)
            return KSBA_Out_Of_Core;
        }

      if (ti.nhdr + d->image.used >= d->image.length)
        return set_error (d, NULL, "image buffer too short to store the tag");
      memcpy (d->image.buf + d->image.used, ti.buf, ti.nhdr);
      d->image.used += ti.nhdr;
    }
  

  if (!d->bypass)
    {
      int again, endtag;

      do
        {
          again = endtag = 0;
          switch ( ds->cur.in_any? 4 
                   : (ti.class == CLASS_UNIVERSAL && !ti.tag)? (endtag=1,5)
                   : match_der (d->root, &ti, ds, &node, debug))
            { 
            case -1:
              if (debug)
                {
                  printf ("   FAIL <"); dump_tlv (&ti, stdout); printf (">\n");
                }
              if (d->honor_module_end)
                {
                  /* We must push back the stuff we already read */
                  ksba_reader_unread (d->reader, ti.buf, ti.nhdr);
                  return -1; 
                }
              else
                d->bypass = 1;
              break;
            case 0:
              if (debug)
                puts ("  End of description");
              d->bypass = 1;
              break;
            case 1: /* again */
              if (debug)
                printf ("  Again\n");
              again = 1;
              break;
            case 2: /* use default value +  again*/
              if (debug)
                printf ("  Using default\n");
              again = 1;
              break;
            case 4: /* match of ANY on a constructed type */
              if (debug)
                  printf ("  ANY");
              ds->cur.in_any = 1;
            case 3: /* match */ 
            case 5: /* end tag */
              if (debug)
                {
                  printf ("  Match <"); dump_tlv (&ti, stdout); printf (">\n");
                  if (ti.tag == TYPE_OCTET_STRING && ti.length == 64)
                    printf ("  DEBUG POINT\n");
                }
              /* increment by the header length */
              ds->cur.nread += ti.nhdr;
                  
              if (!ti.is_constructed)
                  ds->cur.nread += ti.length;

              ds->cur.went_up = 0;
              do
                {
                  if (debug)
                    printf ("  (length %d nread %d) %s\n",
                            ds->idx? ds->stack[ds->idx-1].length:-1,
                            ds->cur.nread,
                            ti.is_constructed? "con":"pri");

                  if ( ds->idx
                       && !ds->stack[ds->idx-1].ndef_length
                       && (ds->cur.nread
                           > ds->stack[ds->idx-1].length)) 
                    {
                      fprintf (stderr, "  ERROR: object length field %d octects"
                               " too large\n",   
                              ds->cur.nread > ds->cur.length);
                      ds->cur.nread = ds->cur.length;
                    }
                  if ( ds->idx
                       && (endtag
                           || (!ds->stack[ds->idx-1].ndef_length
                               && (ds->cur.nread
                                   >= ds->stack[ds->idx-1].length)))) 
                    {
                      int n = ds->cur.nread;
                      pop_decoder_state (ds);
                      ds->cur.nread += n;
                      ds->cur.went_up++;
                    }
                  endtag = 0;
                }
              while ( ds->idx
                      && !ds->stack[ds->idx-1].ndef_length
                      && (ds->cur.nread
                          >= ds->stack[ds->idx-1].length));
                  
              if (ti.is_constructed)
                {
                  /* prepare for the next level */
                  ds->cur.length = ti.length;
                  ds->cur.ndef_length = ti.ndef;
                  push_decoder_state (ds);
                  ds->cur.length = 0;
                  ds->cur.ndef_length = 0;
                  ds->cur.nread = 0;
                }
              if (debug)
                printf ("  (length %d nread %d) end\n",
                        ds->idx? ds->stack[ds->idx-1].length:-1,
                        ds->cur.nread);
              break;
            default:
              never_reached ();
              abort (); 
              break;
            }
        }
      while (again);
    }

  d->val.primitive = !ti.is_constructed;
  d->val.length = ti.length;
  d->val.nhdr = ti.nhdr;
  d->val.tag  = ti.tag; /* kludge to fix TYPE_ANY probs */
  d->val.is_endtag = (ti.class == CLASS_UNIVERSAL && !ti.tag); 
  d->val.node = d->bypass? NULL : node;
  if (debug)
    dump_decoder_state (ds);
  
  return 0;
}

static KsbaError
decoder_skip (DerEncoder d)
{
  if (d->val.primitive)
    { 
      if (read_buffer (d->reader, NULL, d->val.length))
        return eof_or_error (d, 1);
    }
  return 0;
}



/* Calculate the distance between the 2 nodes */
static int
distance (AsnNode root, AsnNode node)
{
  int n=0;

  while (node && node != root)
    {
      while (node->left && node->left->right == node)
        node = node->left;
      node = node->left;
      n++;
    }

  return n;
}


/**
 * _ksba_der_encoder_dump:
 * @d: Decoder object
 * 
 * Dump a textual representation of the encoding to the given stream.
 * 
 * Return value: 
 **/
KsbaError
_ksba_der_encoder_dump (DerEncoder d, FILE *fp)
{
  KsbaError err;
  int depth = 0;
  AsnNode node;
  unsigned char *buf = NULL;
  size_t buflen = 0;;

  if (!d)
    return KSBA_Invalid_Value;

  d->debug = !!getenv("DEBUG_DER_ENCODER");
  d->use_image = 0;
  d->image.buf = NULL;
  err = decoder_init (d, NULL);
  if (err)
    return err;

  while (!(err = decoder_next (d)))
    {
      node = d->val.node;
      if (node)
        depth = distance (d->root, node);

      fprintf (fp, "%4lu %4u:%*s",
               ksba_reader_tell (d->reader) - d->val.nhdr,
               d->val.length,
               depth*2, "");
      if (node)
        _ksba_asn_node_dump (node, fp);
      else
        fputs ("[No matching node]", fp);

      if (node && d->val.primitive)
        {
          int i, n, c;
          char *p;
      
          if (!buf || buflen < d->val.length)
            {
              xfree (buf);
              buflen = d->val.length + 100;
              buf = xtrymalloc (buflen);
              if (!buf)
                err = KSBA_Out_Of_Core;
            }

          for (n=0; !err && n < d->val.length; n++)
            {
              if ( (c=read_byte (d->reader)) == -1)
                err =  eof_or_error (d, 1);
              buf[n] = c;
            }
          if (err)
            break;
          fputs ("  (", fp);
          p = NULL;
          switch (node->type)
            {
            case TYPE_OBJECT_ID:
              p = ksba_oid_to_str (buf, n);
              break;
            default:
              for (i=0; i < n && i < 20; i++)
                fprintf (fp,"%02x", buf[i]);
              if (i < n)
                fputs ("..more..", fp);
              break;
            }
          if (p)
            {
              fputs (p, fp);
              xfree (p);
            }
          fputs (")\n", fp);
        }
      else
        {
          err = decoder_skip (d);
          putc ('\n', fp);
        }
      if (err)
        break;

    }
  if (err == -1)
    err = 0;

  decoder_deinit (d);
  xfree (buf);
  return err;
}




KsbaError
_ksba_der_encoder_encode (DerEncoder d, const char *start_name,
                          AsnNode *r_root,
                          unsigned char **r_image, size_t *r_imagelen)
{
  KsbaError err;
  AsnNode node;
  unsigned char *buf = NULL;
  size_t buflen = 0;
  unsigned long startoff;

  if (!d)
    return KSBA_Invalid_Value;

  if (r_root)
    *r_root = NULL;

  d->debug = !!getenv("DEBUG_DER_ENCODER");
  d->honor_module_end = 1;
  d->use_image = 1;
  d->image.buf = NULL;

  startoff = ksba_reader_tell (d->reader);

  err = decoder_init (d, start_name);
  if (err)
    return err;

  while (!(err = decoder_next (d)))
    {
      int n, c;

      node = d->val.node;
      if (node && d->use_image)
        {
          if (!d->val.is_endtag)
            { /* We don't have nodes for the end tag - so don't store it */
              node->off = (ksba_reader_tell (d->reader)
                           - d->val.nhdr - startoff);
              node->nhdr = d->val.nhdr;
              node->len = d->val.length;
              if (node->type == TYPE_ANY)
                node->actual_type = d->val.tag;
            }
          if (d->image.used + d->val.length > d->image.length)
            err = set_error(d, NULL, "TLV length too large");
          else if (d->val.primitive)
            {
              if( read_buffer (d->reader,
                               d->image.buf + d->image.used, d->val.length))
                err = eof_or_error (d, 1);
              else
                d->image.used += d->val.length;
            }
        }
      else if (node && d->val.primitive)
        {
          if (!buf || buflen < d->val.length)
            {
              xfree (buf);
              buflen = d->val.length + 100;
              buf = xtrymalloc (buflen);
              if (!buf)
                err = KSBA_Out_Of_Core;
            }

          for (n=0; !err && n < d->val.length; n++)
            {
              if ( (c=read_byte (d->reader)) == -1)
                err =  eof_or_error (d, 1);
              buf[n] = c;
            }
          if (err)
            break;

          switch (node->type)
            {
            default:
              _ksba_asn_set_value (node, VALTYPE_MEM, buf, n);
              break;
            }
        }
      else
        {
          err = decoder_skip (d);
        }
      if (err)
        break;
    }
  if (err == -1)
    err = 0;

  if (r_root && !err)
    {
      if (!d->image.buf)
        { /* Not even the first node available - return eof */
          /* fixme: release d->root */
          d->root = NULL;
          err = -1;
        }
      
      fixup_type_any (d->root);
      *r_root = d->root;
      d->root = NULL;
      *r_image = d->image.buf;
      d->image.buf = NULL;
      *r_imagelen = d->image.used;
      if (d->debug)
        {
          fputs ("Value Tree:\n", stdout); 
          _ksba_asn_node_dump_all (*r_root, stdout); 
        }
    }

  decoder_deinit (d);
  xfree (buf);
  return err;
}

#endif


/*
  Helpers to construct and write out objects
*/


/* Create and write a

  AlgorithmIdentifier ::= SEQUENCE {
      algorithm    OBJECT IDENTIFIER,
      parameters   ANY DEFINED BY algorithm OPTIONAL 
  }

  where parameters will be set to NULL if parm is NULL or to an octet
  string conating the given parm */
KsbaError
_ksba_der_write_algorithm_identifier (KsbaWriter w, const char *oid,
                                      const void *parm, size_t parmlen)
{
  KsbaError err;
  char *buf;
  size_t len;

  err = ksba_oid_from_str (oid, &buf, &len);
  if (err)
    return err;

  /* write the sequence */
  /* fixme: the the length to encode the TLV values are actually not
     just 2 bute each but doe penden on the length of the values - for
     our purposes the static values to work */
  err = _ksba_ber_write_tl (w, TYPE_SEQUENCE, CLASS_UNIVERSAL, 1,
                            4 + len + (parm? parmlen:0));
  if (err)
    goto leave;

  /* the OBJECT ID header and the value */
  err = _ksba_ber_write_tl (w, TYPE_OBJECT_ID, CLASS_UNIVERSAL, 0, len);
  if (!err)
    err = ksba_writer_write (w, buf, len);
  if (err)
    goto leave;

  /* Write the parameter */
  if (parm)
    {
      err = _ksba_ber_write_tl (w, TYPE_OCTET_STRING, CLASS_UNIVERSAL,
                                0, parmlen);
      if (!err)
        err = ksba_writer_write (w, parm, parmlen);
    }
  else
    {
      err = _ksba_ber_write_tl (w, TYPE_NULL, CLASS_UNIVERSAL, 0, 0);
    }

 leave:
  xfree (buf);
  return err;
}





/*************************************************
 ***  Copy data from a tree image to the tree  ***
 *************************************************/

/* Copy all values from the tree SRC (with values store in SRCIMAGE)
   to the tree DST */
KsbaError
_ksba_der_copy_tree (AsnNode dst_root,
                     AsnNode src_root, const unsigned char *src_image)
{
  AsnNode s, d;

  s = src_root;
  d = dst_root;
  /* note: we use the is_any flags becuase an inserted copy may have
     already changed the any tag to the actual type */
  while (s && d && (s->type == d->type || d->flags.is_any))
    {
      if (d->flags.is_any)
        d->type = s->type;

      if (s->flags.in_array && s->right)
        {
          if (!_ksba_asn_insert_copy (d))
            return KSBA_Out_Of_Core;
        }

      if ( !_ksba_asn_is_primitive (s->type) )
        ;
      else if (s->off == -1)
        clear_value (d);
      else
        store_value (d, src_image + s->off + s->nhdr, s->len);

      s = _ksba_asn_walk_tree (src_root, s);
      d = _ksba_asn_walk_tree (dst_root, d);
    }

  if (s || d)
    {
      fputs ("ksba_der_copy_tree: trees don't match\nSOURCE TREE:\n", stderr);
      _ksba_asn_node_dump_all (src_root, stderr);
      fputs ("DESTINATION TREE:\n", stderr);
      _ksba_asn_node_dump_all (dst_root, stderr);
      return KSBA_Encoding_Error;
    }
  return 0;
}



/*********************************************
 ********** Store data in a tree *************
 *********************************************/


KsbaError
_ksba_der_store_time (AsnNode node, time_t atime)
{
  char buf[50], *p;
  struct tm *tp;
  int need_gen;

  tp = gmtime (&atime);
  sprintf (buf, "%04d%02d%02d%02d%02d%02dZ",
           1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
           tp->tm_hour, tp->tm_min, tp->tm_sec);
  need_gen = tp->tm_year >= 150;

  if (node->type == TYPE_ANY)
    node->type = need_gen? TYPE_GENERALIZED_TIME : TYPE_UTC_TIME;
  else if (node->type == TYPE_CHOICE)
    { /* find a suitable choice to store the value */
      AsnNode n;

      for (n=node->down; n; n=n->right)
        {
          if ( (need_gen && n->type == TYPE_GENERALIZED_TIME)
               || (!need_gen && n->type == TYPE_UTC_TIME))
            {
              node = n;
              break;
            }
        }
    }
  
  if (node->type == TYPE_GENERALIZED_TIME
      || node->type == TYPE_UTC_TIME)
    {
      p = node->type == TYPE_UTC_TIME? (buf+2):buf;
      return store_value (node, p, strlen (p));
    }
  else
    return KSBA_Invalid_Value;
}

/* Store the utf-8 STRING in NODE. */
KsbaError
_ksba_der_store_string (AsnNode node, const char *string)
{
  if (node->type == TYPE_CHOICE)
    {
      /* find a suitable choice to store the value */
    }


  if (node->type == TYPE_PRINTABLE_STRING)
    {
      return store_value (node, string, strlen (string));
    }
  else
    return KSBA_Invalid_Value;
}


/* Store the integer VALUE in NODE.  VALUE is assumed to be a DER
   encoded integer prefixed with 4 bytes given its length in network
   byte order. */
KsbaError
_ksba_der_store_integer (AsnNode node, const unsigned char *value)
{
  if (node->type == TYPE_INTEGER)
    {
      size_t len;
      
      len = (value[0] << 24) | (value[1] << 16) | (value[2] << 8) | value[3];
      return store_value (node, value+4, len);
    }
  else
    return KSBA_Invalid_Value;
}

KsbaError
_ksba_der_store_oid (AsnNode node, const char *oid)
{
  KsbaError err;

  if (node->type == TYPE_OBJECT_ID)
    {
      char *buf;
      size_t len;

      err = ksba_oid_from_str (oid, &buf, &len);
      if (err)
        return err;
      err = store_value (node, buf, len);
      xfree (buf);
      return err;
    }
  else
    return KSBA_Invalid_Value;
}


KsbaError
_ksba_der_store_octet_string (AsnNode node, const char *buf, size_t len)
{
  if (node->type == TYPE_ANY)
    node->type = TYPE_OCTET_STRING;

  if (node->type == TYPE_OCTET_STRING)
    {
      return store_value (node, buf, len);
    }
  else
    return KSBA_Invalid_Value;
}

KsbaError
_ksba_der_store_null (AsnNode node)
{
  if (node->type == TYPE_ANY)
    node->type = TYPE_NULL;

  if (node->type == TYPE_NULL)
    {
      return store_value (node, "", 0);
    }
  else
    return KSBA_Invalid_Value;
}


/* 
   Actual DER encoder
*/

/* We have a value for this node.  Calculate the length of the header
   and store it in node->nhdr and store the length of the value in
   node->value. We assume that this is a primitive node and has a
   value of type VALTYPE_MEM. */
static void
set_nhdr_and_len (AsnNode node, unsigned long length)
{
  int buflen = 0;

  if (node->type == TYPE_SET_OF || node->type == TYPE_SEQUENCE_OF)
    buflen++;
  else if (node->type == TYPE_TAG)
    buflen++; 
  else if (node->type < 0x1f)
    buflen++;
  else
    {
      never_reached ();
      /* FIXME: tags with values above 31 are not yet implemented */
    }

  if (!node->type /*&& !class*/)
    buflen++; /* end tag */
  else if (node->type == TYPE_NULL /*&& !class*/)
    buflen++; /* NULL tag */
  else if (!length)
    buflen++; /* indefinite length */
  else if (length < 128)
    buflen++; 
  else 
    {
      buflen += (length <= 0xff ? 2:
                 length <= 0xffff ? 3: 
                 length <= 0xffffff ? 4: 5);
    }        

  node->len = length;
  node->nhdr = buflen;
}

/* Like above but put now put it into buffer.  return the number of
   bytes copied.  There is no need to do length checking here */
static size_t
copy_nhdr_and_len (unsigned char *buffer, AsnNode node)
{
  unsigned char *p = buffer;
  int tag, class;
  unsigned long length;

  tag = node->type;
  class = CLASS_UNIVERSAL;
  length = node->len;

  if (tag == TYPE_SET_OF)
    tag = TYPE_SET;
  else if (tag == TYPE_SEQUENCE_OF)
    tag = TYPE_SEQUENCE;
  else if (tag == TYPE_TAG)
    {
      class = CLASS_CONTEXT;  /* Hmmm: we no way to handle other classes */
      tag = node->value.v_ulong;
    }
  if (tag < 0x1f)
    {
      *p = (class << 6) | tag;
      if (!_ksba_asn_is_primitive (tag))
        *p |= 0x20;
      p++;
    }
  else
    {
      /* fixme: Not_Implemented*/
    }

  if (!tag && !class)
    *p++ = 0; /* end tag */
  else if (tag == TYPE_NULL && !class)
    *p++ = 0; /* NULL tag */
  else if (!length)
    *p++ = 0x80; /* indefinite length - can't happen! */
  else if (length < 128)
    *p++ = length; 
  else 
    {
      int i;

      /* fixme: if we know the sizeof an ulong we could support larger
         objetcs - however this is pretty ridiculous */
      i = (length <= 0xff ? 1:
           length <= 0xffff ? 2: 
           length <= 0xffffff ? 3: 4);
      
      *p++ = (0x80 | i);
      if (i > 3)
        *p++ = length >> 24;
      if (i > 2)
        *p++ = length >> 16;
      if (i > 1)
        *p++ = length >> 8;
      *p++ = length;
    }        

  return p - buffer;
}



static unsigned long
sum_up_lengths (AsnNode root)
{
  AsnNode n;
  unsigned long len = 0;

  if (!(n=root->down) || _ksba_asn_is_primitive (root->type))
    len = root->len;
  else
    {
      for (; n; n = n->right)
        len += sum_up_lengths (n);
    }
  if ( !_ksba_asn_is_primitive (root->type)
       && root->type != TYPE_CHOICE
       && len
       && !root->flags.is_implicit)
    { /* this is a constructed one */
      set_nhdr_and_len (root, len);
    }

  return len? (len + root->nhdr):0;
}

/* Create a DER encoding from the value tree ROOT and return an
   allocated image of appropriate length in r_imae and r_imagelen.
   The value tree is modified so that it can be used the same way as a
   parsed one, i.e the elements off, and len are set to point into
   image. */
KsbaError
_ksba_der_encode_tree (AsnNode root,
                       unsigned char **r_image, size_t *r_imagelen)
{
  AsnNode n;
  unsigned char *image;
  size_t imagelen, len;

  /* clear out all fields */
  for (n=root; n ; n = _ksba_asn_walk_tree (root, n))
    {
      n->off = -1;
      n->len = 0;
      n->nhdr = 0;
    }
     
  /* Set default values */
  /* FIXME */

  /* calculate the length of the headers.  These are the tag and
     length fields of all primitive elements */
  for (n=root; n ; n = _ksba_asn_walk_tree (root, n))
    {
      if (_ksba_asn_is_primitive (n->type)
          && n->valuetype == VALTYPE_MEM
          && n->value.v_mem.len 
          && !n->flags.is_implicit)
        set_nhdr_and_len (n, n->value.v_mem.len);
    }

  /* Now calculate the length of all constructed types */
  imagelen = sum_up_lengths (root);

#if 0
  /* set off to zero, so that it can be dumped */
  for (n=root; n ; n = _ksba_asn_walk_tree (root, n))
      n->off = 0;
  fputs ("DER encoded value Tree:\n", stderr); 
  _ksba_asn_node_dump_all (root, stderr); 
  for (n=root; n ; n = _ksba_asn_walk_tree (root, n))
      n->off = -1;
#endif
  
  /* now we can create an encoding in image */
  image = xtrymalloc (imagelen);
  if (!image)
    return KSBA_Out_Of_Core;
  len = 0;
  for (n=root; n ; n = _ksba_asn_walk_tree (root, n))
    {
      size_t nbytes;

      if (!n->nhdr)
        continue;
      assert (n->off == -1);
      assert (len < imagelen);
      n->off = len;
      nbytes = copy_nhdr_and_len (image+len, n);
      len += nbytes;
      if ( _ksba_asn_is_primitive (n->type)
           && n->valuetype == VALTYPE_MEM
           && n->value.v_mem.len )
        {
          nbytes = n->value.v_mem.len;
          assert (len + nbytes <= imagelen);
          memcpy (image+len, n->value.v_mem.buf, nbytes);
          len += nbytes;
        }
    }

  assert (len == imagelen);

  *r_image = image;
  if (r_imagelen)
    *r_imagelen = imagelen;
  return 0;
}











