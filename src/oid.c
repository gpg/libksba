/* oid.c - Object identifier helper functions
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


/**
 * ksba_oid_to_str:
 * @buffer: A BER encoded OID
 * @length: The length of this OID
 * 
 * Take a buffer with an object identifier in BER encoding and return
 * a string representing this OID.  We do not use the ASN.1 syntax
 * here but delimit the arcs with dots, so it is easier to parse in
 * most cases.  This dotted-decimal notation is also known as LDAPOID
 * string and described in RFC-2251.
 *
 * The function returns an emtry string for an empty buffer and does
 * no interpretation of the OID.  The caller must free the returned
 * string using ksba_free() or the function he has registered as a
 * replacement.
 * 
 *
 * Return value: A allocated string or NULL in case of memory problem.
 **/
char *
ksba_oid_to_str (const char *buffer, size_t length)
{
  const unsigned char *buf = buffer;
  char *string, *p;
  int n = 0;
  unsigned long val;

  /* To calculate the length of the string we can safely assume an
     upper limit of 3 decimal characters per byte.  Two extra bytes
     account for the special first octect */
  string = p = xtrymalloc (length*(1+3)+2+1);
  if (!string)
    return NULL;
  if (!length)
    {
      *p = 0;
      return string;
    }

  /* fixme: open code the sprintf so that we can open with arbitrary
     long integers - at least we should check for overflow of ulong */

  if (buf[0] < 40)
    p += sprintf (p, "0.%d", buf[n]);
  else if (buf[0] < 80)
    p += sprintf (p, "1.%d", buf[n]-40);
  else {
    val = buf[n] & 0x7f;
    while ( (buf[n]&0x80) && ++n < length )
      {
        val <<= 7;
        val |= buf[n] & 0x7f;
      }
    val -= 80;
    sprintf (p, "2.%lu", val);
    p += strlen (p);
  }
  for (n++; n < length; n++)
    {
      val = buf[n] & 0x7f;
      while ( (buf[n]&0x80) && ++n < length )
        {
          val <<= 7;
          val |= buf[n] & 0x7f;
        }
      sprintf (p, ".%lu", val);
      p += strlen (p);
    }
    
  *p = 0;
  return string;
}


/**
 * ksba_oid_from_str:
 * @string: A string with the OID in doitted decimal form
 * @rbuf:   Returns the DER encoded OID
 * @rlength: and its length
 * 
 * Convertes the OID given in dotted decimal form to an DER encoding
 * and returns it in allocated buffer rbuf and its length in rlength.
 * rbuf is set to NULL in case of an error and -1 is returned.
 * Scanning stops at the first white space.

 * The caller must free the returned buffer using ksba_free() or the
 * function he has registered as a replacement.
 * 
 * Return value: Number of bytes scanned from string, or -1 in case of
 * an error.
 **/
int
ksba_oid_from_str (const char *string, char **rbuf, size_t *rlength)
{
  *rbuf = NULL;
  *rlength = 0;

  return -1; /* error */
}




