/* name.c - Object to access GeneralNames etc.
 *      Copyright (C) 2002 g10 Code GmbH
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
#include "asn1-func.h"
#include "convert.h"
#include "ber-help.h"


struct ksba_name_s {
  int ref_count;
  int n_names;   /* number of names */
  char **names;  /* array with the parsed names */
};


/* Also this is a public function it is not yet usable becuase we
   don't have a way to set real information.  */
KsbaName
ksba_name_new (void)
{
  KsbaName name;

  name = xtrycalloc (1, sizeof *name);
  if (!name)
    return NULL;
  name->ref_count++;

  return name;
}

void
ksba_name_ref (KsbaName name)
{
  if (!name)
    fprintf (stderr, "BUG: ksba_name_ref for NULL\n");
  else
    ++name->ref_count;
}


void
ksba_name_release (KsbaName name)
{
  int i;

  if (!name)
    return;
  if (name->ref_count < 1)
    {
      fprintf (stderr, "BUG: trying to release an already released name\n");
      return;
    }
  if (--name->ref_count)
    return;

  for (i=0; i < name->n_names; i++)
    xfree (name->names[i]);
  xfree (name->names);
  name->n_names = 0;
  xfree (name);
}


/* This is an internal function to create an KsbaName object from an
   DER encoded image which must point to an GeneralNames object */
KsbaError 
_ksba_name_new_from_der (KsbaName *r_name,
                         const unsigned char *image, size_t imagelen)
{
  KsbaError err;
  KsbaName name;
  struct tag_info ti;
  const unsigned char *der;
  size_t derlen;
  int n;
  char *p;

  if (!r_name || !image)
    return KSBA_Invalid_Value;

  *r_name = NULL;

  /* count and check for encoding errors - we won;t do this again
     during the second pass */
  der = image;
  derlen = imagelen;
  n = 0;
  while (derlen)
    {
      err = _ksba_ber_parse_tl (&der, &derlen, &ti);
      if (err)
        return err;
      if (ti.class != CLASS_CONTEXT) 
        return KSBA_Invalid_Cert_Object; /* we expected a tag */
      if (ti.ndef)
        return KSBA_Not_DER_Encoded;
      if (derlen < ti.length)
        return KSBA_BER_Error;
      switch (ti.tag)
        {
        case 1: /* rfc822Name - this is an imlicit IA5_STRING */
        case 6: /* URI */
          n++;
          break;
        default: 
          break;
        }

      /* advance pointer */
      der += ti.length;
      derlen -= ti.length;
    }

  /* allocate array and set all slots to NULL for easier error recovery */
  name = ksba_name_new ();
  if (!name)
    return KSBA_Out_Of_Core;
  if (!n)
    return 0; /* empty GeneralNames */
  name->names = xtrycalloc (n, sizeof *name->names);
  if (!name->names)
    {
      ksba_name_release (name);
      return KSBA_Out_Of_Core;
    }
  name->n_names = n;

  /* start the second pass */
  der = image;
  derlen = imagelen;
  n = 0;
  while (derlen)
    {
      char numbuf[21];

      err = _ksba_ber_parse_tl (&der, &derlen, &ti);
      assert (!err);
      switch (ti.tag)
        {
        case 1: /* rfc822Name - this is an imlicit IA5_STRING */
          p = name->names[n] = xtrymalloc (ti.length+3);
          if (!p)
            {
              ksba_name_release (name);
              return KSBA_Out_Of_Core;
            }
          *p++ = '<';
          memcpy (p, der, ti.length);
          p += ti.length;
          *p++ = '>';
          *p = 0;
          n++;
          break;
        case 6: /* URI */
          sprintf (numbuf, "%u:", (unsigned int)ti.length);
          p = name->names[n] = xtrymalloc (1+5+strlen (numbuf)
                                           + ti.length +1+1);
          if (!p)
            {
              ksba_name_release (name);
              return KSBA_Out_Of_Core;
            }
          p = stpcpy (p, "(3:uri");
          p = stpcpy (p, numbuf);
          memcpy (p, der, ti.length);
          p += ti.length;
          *p++ = ')';
          *p = 0; /* extra safeguard null */
          n++;
          break;
        default: 
          break;
        }

      /* advance pointer */
      der += ti.length;
      derlen -= ti.length;
    }
  *r_name = name;
  return 0;
}


/* By iterating IDX up starting with 0, this function returns the all
   General Names stored in NAME. The format of the returned name is
   either a RFC-2253 formated one which can be detected by checking
   whether the first character is letter or a digit.  RFC 2822 conform
   email addresses are returned enclosed in angle brackets, the
   opening angle bracket should be used to detect this.  Other formats
   are returned as an S-Expression in canonical format, so a opening
   parenthesis may be used to detect this encoding, in this case the
   name may include binary null characters, so strlen might return a
   length shorter than actually used, the real length is implictly
   given by the structure of the S-Exp, an extra null is appended for
   safety reasons.  One common format return is probably an Universal
   Resource Identifier which has the S-expression: "(uri <urivalue>)".

   The return string has the same lifetime as NAME. */
const char *
ksba_name_enum (KsbaName name, int idx)
{
  if (!name || idx < 0)
    return NULL;
  if (idx >= name->n_names)
    return NULL;  /* end of list */

  return name->names[idx];
}

/* Convenience function to return names representing an URI.  Caller
   must free the return value.  Note that this function should not be
   used for enumeration */
char *
ksba_name_get_uri (KsbaName name, int idx)
{
  const char *s = ksba_name_enum (name, idx);
  int n;
  char *buf;

  if (!s || strncmp (s, "(3:uri", 6))
    return NULL;  /* we do only return URIs */
  s += 6;
  for (n=0; *s && *s != ':' && digitp (s); s++)
    n = n*10 + atoi_1 (s);
  if (!n || *s != ':')
    return NULL; /* oops */
  s++;
  buf = xtrymalloc (n+1);
  if (buf)
    {
      memcpy (buf, s, n);
      buf[n] = 0;
    }
  return buf;
}
