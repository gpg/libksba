/* keyinfo.c - Parse and build a keyInfo structure
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

/* Instead of using the ASN parser - which is easily possible - we use
   a simple handcoded one to speed the oepration up and make it more
   robust. */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "asn1-func.h"


struct {
  const unsigned char *oid;  /* NULL indicattes end of table */
  int                  oidlen;


} algo_table[] = {
  {"\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01", 11, 
   /* 1.2.840.113549.1.1.1  rsaEncryption (pkcs#1) */ }


  {NULL}
};





#define TLV_LENGTH() do {         \
  if (!derlen)                    \
    return KSBA_Invalid_Keyinfo;  \
  c = *der++; derlen--;           \
  if (c == 0x80)                  \
    return KSBA_Not_DER_Encoded;  \
  if (c == 0xff)                  \
    return KSBA_BER_Error;        \
                                  \
  if ( !(c & 0x80) )              \
    len = c;                      \
  else                            \
    {                             \
      int count = c & 0x7f;       \
                                  \
      for (len=0; count; count--) \
        {                         \
          len <<= 8;              \
          if (!derlen)            \
            return KSBA_BER_Error;\
          c = *der++; derlen--;   \
          len |= c & 0xff;        \
        }                         \
    }                             \
  if (len > derlen)               \
    return KSBA_Invalid_Keyinfo;  \
} while (0)


/* Return the OFF and the LEN of algorithm within DER.  Do some checks
   and return the number of bytes read in r_nread, adding this to der
   does point into the BIT STRING */
static KsbaError
get_algorithm (const unsigned char *der, size_t derlen,
               size_t *r_nread, size_t *r_pos, size_t *r_len)
{
  int c;
  const char *start;
  unsigned long len;

  /* check the outer sequence */
  if (!derlen)
    return KSBA_Invalid_Keyinfo;
  c = *der++; derlen--;
  if ( c != 0x30 )
    return KSBA_Unexpected_Tag; /* not a SEQUENCE */
  TLV_LENGTH();

  /* get the inner sequence */
  if (!derlen)
    return KSBA_Invalid_Keyinfo;
  c = *der++; derlen--;
  if ( c != 0x30 )
    return KSBA_Unexpected_Tag; /* not a SEQUENCE */
  TLV_LENGTH(); 

  /* get the object identifier */
  if (!derlen)
    return KSBA_Invalid_Keyinfo;
  c = *der++; derlen--;
  if ( c != 0x06 )
    return KSBA_Unexpected_Tag; /* not an OBJECT IDENTIFIER */
  TLV_LENGTH();

  /* der does now point to an oid of length LEN */
  *r_off = der - start;
  *r_len = len;
  {
    char *p = ksba_oid_to_str (der, len);
    printf ("algorithm: %s\n", p);
    xfree (p);
  }
  der += len;
  derlen -= len;

  /* check that the parameter is NULL or not there */
  if (!derlen)
    return KSBA_Invalid_Keyinfo;
  c = *der++; derlen--;
  if ( c == 0x05 ) 
    {
      printf ("parameter: NULL\n");
      if (!derlen)
        return KSBA_Invalid_Keyinfo;
      c = *der++; derlen--;
      if (c) 
        return KSBA_BER_Error;  /* NULL must have a length of 0 */
      
      /* move forward to the BIT_STR */
      if (!derlen)
        return KSBA_Invalid_Keyinfo;
      c = *der++; derlen--;
    }
    
  if (c != 0x03)
    return KSBA_Unexpected_Tag; /* not a BIT STRING */
  TLV_LENGTH();

  /* we are now inside the BIT STRING */
  printf ("bit string of %lu bytes\n", len);

  *r_nread = der - start;

  return 0;
}

/* Assume that der is a buffer of length DERLEN with a DER encoded
 Asn.1 structure like this:
 
  keyInfo ::= SEQUENCE {
                 SEQUENCE { 
                    algorithm    OBJECT IDENTIFIER,
                    parameters   ANY DEFINED BY algorithm OPTIONAL }
                 publicKey  BIT STRING }
  
  We only allow parameters == NULL.

  The function parses this structure and create a SEXP suitable to be
  used as a public key in Libgcrypt.  The S-Exp will be returned in a
  string which the caller must free.  
  
  We don't pass an ASN.1 node here but a plain memory block.  */

KsbaError
_ksba_keyinfo_to_sexp (const unsigned char *der, size_t derlen,
                       char **r_string)
{
  KsbaError err;
  size_t nread, off, len;
  int algoidx;

  *r_string = NULL;

  printf ("parsing keyinfo ...\n");

  err = get_algorithm (der, derlen, &nread, &off, &len);
  if (err)
    return err;
  
  /* look into our table of supported algorithms */
  for (algoidx=0; algo_table[algoidx].oid; algoidx++)
    {
      if ( len == algo_table[algoidx].oidlen
           && !memcmp (der+off, algo_table[algoidx].oid, len))
        break;
    }
  if (!algo_table[algoidx].oid)
    return KSAB_Unknown_Algorithm;

  WORK



  return 0;
}





