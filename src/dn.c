/* dn.c - Distinguished Name helper functions
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

/* Reference is RFC-2253 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "asn1-func.h"

struct {
  const char *name;
  int allowed_by_sphinx;
  const char *description;
  int                  oidlen;
  const unsigned char *oid;
} oid_name_tbl[] = { /* see rfc2256 for a list of them */
{"CN", 1, "CommonName",            3, "\x55\x04\x03"}, /* 2.5.4.3 */
{"SN", 1, "SurName",               3, "\x55\x04\x04"}, /* 2.5.4.4 */
{"SERIALNUMBER", 0, "SerialNumber",3, "\x55\x04\x05"}, /* 2.5.4.5 */
{"C",  1, "CountryName",           3, "\x55\x04\x06"}, /* 2.5.4.6 */
{"L" , 1, "LocalityName",          3, "\x55\x04\x07"}, /* 2.5.4.7 */
{"ST", 1, "StateOrProvince",       3, "\x55\x04\x08"}, /* 2.5.4.8 */
{"STREET", 0, "StreetAddress",     3, "\x55\x04\x09"}, /* 2.5.4.9 */
{"O",  1, "OrganizationName",      3, "\x55\x04\x0a"}, /* 2.5.4.10 */
{"OU", 1, "OrganizationalUnit",    3, "\x55\x04\x0b"}, /* 2.5.4.11 */
{"TITLE",1, "Title",               3, "\x55\x04\x0c"}, /* 2.5.4.12 */
{"DESCRIPTION",
       0, "Description",           3, "\x55\x04\x0d"}, /* 2.5.4.13 */
{"BUSINESSCATEGORY",
       1, "BusinessCategory",      3, "\x55\x04\x0f"}, /* 2.5.4.15 */
{"POSTALADDRESS",
       0, "PostalAddress",         3, "\x55\x04\x11"}, /* 2.5.4.16 */
{"POSTALCODE" , 1, "PostalCode",   3, "\x55\x04\x11"}, /* 2.5.4.17 */
{"GIVENNAME"  , 1, "GivenName",    3, "\x55\x04\x2a"}, /* 2.5.4.42 */
{"DC", 0, "domainComponent",      10, 
       "\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x01"},
                            /* 0.9.2342.19200300.100.1.25 */

/* {"UID","userid",}  FIXME: I don't have the OID  it might be ...100.1.1 */
{ NULL }
};


struct stringbuf {
  size_t len;
  size_t size;
  char *buf;
  int out_of_core;
};



static void
init_stringbuf (struct stringbuf *sb, int initiallen)
{
  sb->len = 0;
  sb->size = initiallen;
  sb->out_of_core = 0;
  /* allocate one more, so that get_stringbuf can append a nul */
  sb->buf = xtrymalloc (initiallen+1);
  if (!sb->buf)
      sb->out_of_core = 1;
}

static void
deinit_stringbuf (struct stringbuf *sb)
{
  xfree (sb->buf); 
  sb->buf = NULL;
  sb->out_of_core = 1; /* make sure the caller does an init before reuse */
}


static void
put_stringbuf (struct stringbuf *sb, const char *text)
{
  size_t n = strlen (text);

  if (sb->out_of_core)
    return;

  if (sb->len + n >= sb->size)
    {
      char *p;
      
      sb->size += n + 100;
      p = xtryrealloc (sb->buf, sb->size);
      if ( !p)
        {
          sb->out_of_core = 1;
          return;
        }
      sb->buf = p;
    }
  memcpy (sb->buf+sb->len, text, n);
  sb->len += n;
}

/* FIXME: This function is a temporary kludge */
static void
put_stringbuf_mem (struct stringbuf *sb, const char *text, size_t n)
{
  if (sb->out_of_core)
    return;

  if (sb->len + n >= sb->size)
    {
      char *p;
      
      sb->size += n + 100;
      p = xtryrealloc (sb->buf, sb->size);
      if ( !p)
        {
          sb->out_of_core = 1;
          return;
        }
      sb->buf = p;
    }
  memcpy (sb->buf+sb->len, text, n);
  sb->len += n;
}

static char *
get_stringbuf (struct stringbuf *sb)
{
  char *p;

  if (sb->out_of_core)
    {
      xfree (sb->buf); sb->buf = NULL;
      return NULL;
    }

  sb->buf[sb->len] = 0;
  p = sb->buf;
  sb->buf = NULL;
  sb->out_of_core = 1; /* make sure the caller does an init before reuse */
  return p;
}




/* Append VALUE of LENGTH and TYPE to SB.  Do the required quoting. */
static void
append_utf8_value (const unsigned char *value, size_t length,
                   struct stringbuf *sb)
{
  /* FIXME */
  put_stringbuf_mem (sb, value, length);
}

/* Append VALUE of LENGTH and TYPE to SB.  Do character set conversion
   and quoting */
static void
append_latin1_value (const unsigned char *value, size_t length,
                     struct stringbuf *sb)
{
  unsigned char tmp[2];
  const unsigned char *s = value;
  size_t n = 0;

  for (;;)
    {
      for (value = s; n < length && !(*s & 0x80); n++, s++)
        ;
      if (s != value)
        put_stringbuf_mem (sb, value, s-value);
      if (n==length)
        return; /* ready */
      assert ((*s & 0x80));
      tmp[0] = 0xc0 | ((*s >> 6) & 3);
      tmp[1] = 0x80 | ( *s & 0x3f );
      put_stringbuf_mem (sb, tmp, 2);
      n++; s++;
    }
}

/* Append attribute and value.  ROOT is the sequence */
static KsbaError
append_atv (const unsigned char *image, AsnNode root, struct stringbuf *sb)
{
  AsnNode node = root->down;
  const char *name;
  int use_hex = 0;
  int i;
  
  if (!node || node->type != TYPE_OBJECT_ID)
    return KSBA_Unexpected_Tag;
  if (node->off == -1)
    return KSBA_No_Value; /* Hmmm, this might lead to misunderstandings */

  name = NULL;
  for (i=0; oid_name_tbl[i].name; i++)
    {
      if (node->len == oid_name_tbl[i].oidlen
          && !memcmp (image+node->off+node->nhdr,
                      oid_name_tbl[i].oid, node->len))
        {
          name = oid_name_tbl[i].name;
          break;
        }
    }
  if (name)
    put_stringbuf (sb, name);
  else
    { /* No name in table: use the oid */
      char *p = ksba_oid_to_str (image+node->off+node->nhdr, node->len);
      if (!p)
        return KSBA_Out_Of_Core;
      put_stringbuf (sb, p);
      xfree (p);
      use_hex = 1;
    }
  put_stringbuf (sb, "=");
  node = node->right;
  if (!node || node->off == -1)
    return KSBA_No_Value;

  switch (use_hex? 0 : node->type)
    {
    case TYPE_UTF8_STRING:
      append_utf8_value (image+node->off+node->nhdr, node->len, sb);
      break;
    case TYPE_PRINTABLE_STRING:
    case TYPE_IA5_STRING:
      /* we assume that wrong encodings are latin-1 */
    case TYPE_TELETEX_STRING: /* most likely latin-1 */
      append_latin1_value (image+node->off+node->nhdr, node->len, sb);
      break;

/*      case TYPE_TELETEX_STRING: */
/*      case TYPE_GRAPHIC_STRING: */
/*      case TYPE_VISIBLE_STRING: */
/*      case TYPE_GENERAL_STRING: */
/*      case TYPE_UNIVERSAL_STRING: */
/*      case TYPE_CHARACTER_STRING: */
/*      case TYPE_BMP_STRING: */
      break;

    case 0: /* forced usage of hex */
    default:
      put_stringbuf (sb, "#");
      for (i=0; i < node->len; i++)
        { 
          char tmp[3];
          sprintf (tmp, "%02X", image[node->off+node->nhdr+i]);
          put_stringbuf (sb, tmp);
        }
      put_stringbuf (sb, "#");
      break;
    }

  return 0;
}

static KsbaError
dn_to_str (const unsigned char *image, AsnNode root, struct stringbuf *sb)
{
  KsbaError err;
  AsnNode nset;

  if (!root )
    return 0; /* empty DN */
  nset = root->down;
  if (!nset)
    return 0; /* consider this as empty */
  if (nset->type != TYPE_SET_OF)
    return KSBA_Unexpected_Tag;

  /* output in reverse order */
  while (nset->right)
    nset = nset->right;

  for (;;)
    {
      AsnNode nseq;

      if (nset->type != TYPE_SET_OF)
        return KSBA_Unexpected_Tag;
      for (nseq = nset->down; nseq; nseq = nseq->right)
        {
          if (nseq->type != TYPE_SEQUENCE)
            return KSBA_Unexpected_Tag;
          if (nseq != nset->down)
            put_stringbuf (sb, "+");
          err = append_atv (image, nseq, sb);
          if (err)
            return err;
        }
      if (nset == root->down)
        break;
      put_stringbuf (sb, ",");
      nset = nset->left;
    }
      
  return 0;
}


KsbaError
_ksba_dn_to_str (const unsigned char *image, AsnNode node, char **r_string)
{
  KsbaError err;
  struct stringbuf sb;

  *r_string = NULL;
  if (!node || node->type != TYPE_SEQUENCE_OF)
    return KSBA_Invalid_Value;

  init_stringbuf (&sb, 100);
  err = dn_to_str (image, node, &sb);
  if (!err)
    {
      *r_string = get_stringbuf (&sb);
      if (!*r_string)
        err = KSBA_Out_Of_Core;
    }
  deinit_stringbuf (&sb);

  return err;
}


KsbaError
_ksba_dn_from_str (const char *string, char **rbuf, size_t *rlength)
{
  return KSBA_Not_Implemented;  /* FIXME*/
}






