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

#include "ksba.h"
#include "util.h"
#include "asn1-func.h"
#include "keyinfo.h"
#include "shared.h"

struct algo_table_s {
  const char *oidstring;
  const unsigned char *oid;  /* NULL indicattes end of table */
  int                  oidlen;
  int supported;
  const char *algo_string;
  const char *elem_string; /* parameter name or '-' */
  const char *ctrl_string; /* expected tag values (value > 127 are raw data)*/
  int digest_algo;
};

static struct algo_table_s pk_algo_table[] = {
  { /* iso.member-body.us.rsadsi.pkcs.pkcs-1.1 */
    "1.2.840.113549.1.1.1", /* rsaEncryption (RSAES-PKCA1-v1.5) */ 
    "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", 9, 
    1, "rsa", "-ne", "\x30\x02\x02" },
  { /* iso.member-body.us.rsadsi.pkcs.pkcs-1.7 */
    "1.2.840.113549.1.1.7", /* RSAES-OAEP */ 
    "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x07", 9, 
    0, "rsa", "-ne", "\x30\x02\x02"}, /* (patent problems) */
  { /* */
    "2.5.8.1.1", /* rsa (ambiguous due to missing padding rules)*/
    "\x55\x08\x01\x01", 4, 
    1, "ambiguous-rsa", "-ne", "\x30\x02\x02" },
  { /* iso.member-body.us.x9-57.x9cm.1 */
    "1.2.840.10040.4.1", /*  dsa */
    "\x2a\x86\x48\xce\x38\x04\x01", 7, 
    1, "dsa"  "y", "\x02" }, 
  /* FIXME: Need code to extract p,q,g from the parameters */

  {NULL}
};


static struct algo_table_s sig_algo_table[] = {
  {  /* iso.member-body.us.rsadsi.pkcs.pkcs-1.5 */
    "1.2.840.113549.1.1.5", /* sha1WithRSAEncryption */ 
    "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05", 9, 
    1, "rsa", "s", "\x82", GCRY_MD_SHA1 },
  { /* iso.member-body.us.rsadsi.pkcs.pkcs-1.4 */
    "1.2.840.113549.1.1.4", /* md5WithRSAEncryption */ 
    "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x04", 9, 
    1, "rsa", "s", "\x82", GCRY_MD_MD5 },
  { /* iso.member-body.us.rsadsi.pkcs.pkcs-1.2 */
    "1.2.840.113549.1.1.2", /* md2WithRSAEncryption */ 
    "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x02", 9, 
    0, "rsa", "s", "\x82", 0 },
  { /* iso.member-body.us.x9-57.x9cm.3 */
    "1.2.840.10040.4.3", /*  dsaWithSha1 */
    "\x2a\x86\x48\xce\x38\x04\x03", 7, 
    1, "dsa", "-rs", "\x30\x02\x02", GCRY_MD_SHA1 }, 
  { /* iso.member-body.us.rsadsi.pkcs.pkcs-1.1 */
    "1.2.840.113549.1.1.1", /* rsaEncryption used without hash algo*/ 
    "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", 9, 
    1, "rsa", "s", "\x82" },
  { /* from NIST's OIW - actually belongs in a pure hash table */
    "1.3.14.3.2.26",  /* sha1 */
    "\x2B\x0E\x03\x02\x1A", 5,
    0, "sha-1", "", "", GCRY_MD_SHA1 },

  {NULL}
};

static struct algo_table_s enc_algo_table[] = {
  { /* iso.member-body.us.rsadsi.pkcs.pkcs-1.1 */
    "1.2.840.113549.1.1.1", /* rsaEncryption (RSAES-PKCA1-v1.5) */ 
    "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01", 9, 
    1, "rsa", "a", "\x82" },
  {NULL}
};


struct stringbuf {
  size_t len;
  size_t size;
  char *buf;
  int out_of_core;
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
   does point into the BIT STRING.

   mode 0: just get the algorithm identifier. FIXME: should be able to
           handle BER Encoding. 
   mode 1: as described.
 */
static KsbaError
get_algorithm (int mode, const unsigned char *der, size_t derlen,
               size_t *r_nread, size_t *r_pos, size_t *r_len, int *r_bitstr,
               size_t *r_parm_pos, size_t *r_parm_len)
{
  int c;
  const unsigned char *start = der;
  const unsigned char *startseq;
  unsigned long seqlen, len;

  *r_bitstr = 0;
  /* get the inner sequence */
  if (!derlen)
    return KSBA_Invalid_Keyinfo;
  c = *der++; derlen--;
  if ( c != 0x30 )
    return KSBA_Unexpected_Tag; /* not a SEQUENCE */
  TLV_LENGTH(); 
  seqlen = len;
  startseq = der;

  /* get the object identifier */
  if (!derlen)
    return KSBA_Invalid_Keyinfo;
  c = *der++; derlen--; 
  if ( c != 0x06 )
    return KSBA_Unexpected_Tag; /* not an OBJECT IDENTIFIER */
  TLV_LENGTH();

  /* der does now point to an oid of length LEN */
  *r_pos = der - start;
  *r_len = len;
/*    { */
/*      char *p = ksba_oid_to_str (der, len); */
/*      printf ("algorithm: %s\n", p); */
/*      xfree (p); */
/*    } */
  der += len;
  derlen -= len;
  seqlen -= der - startseq;;

  /* check that the parameter is NULL or not there */
  if (seqlen)
    {
      const unsigned char *startparm = der;

      if (!derlen)
        return KSBA_Invalid_Keyinfo;
      c = *der++; derlen--;
      if ( c == 0x05 ) 
        {
          /*printf ("parameter: NULL \n"); the only correct thing */
          if (!derlen)
            return KSBA_Invalid_Keyinfo;
          c = *der++; derlen--;
          if (c) 
            return KSBA_BER_Error;  /* NULL must have a length of 0 */
          seqlen -= 2;
        }
      else if (r_parm_pos && r_parm_len && c == 0x04)
        { /* this is an octet string parameter and we need it */
          TLV_LENGTH();
          *r_parm_pos = der - start;
          *r_parm_len = len;
          seqlen -= der - startparm;
          der += len;
          derlen -= len;
          seqlen -= len;
        }
      else
        {
/*            printf ("parameter: with tag %02x - ignored\n", c); */
          TLV_LENGTH();
          seqlen -= der - startparm;
          /* skip the value */
          der += len;
          derlen -= len;
          seqlen -= len;
        }
    }

  if (seqlen)
    return KSBA_Invalid_Keyinfo;

  if (mode)
    {
      /* move forward to the BIT_STR */
      if (!derlen)
        return KSBA_Invalid_Keyinfo;
      c = *der++; derlen--;
      
      if (c == 0x03)
        *r_bitstr = 1; /* BIT STRING */
      else if (c == 0x04)
        ; /* OCTECT STRING */
      else
        return KSBA_Unexpected_Tag; /* not a BIT STRING */
      TLV_LENGTH();
    }

  *r_nread = der - start;
  return 0;
}


KsbaError
_ksba_parse_algorithm_identifier (const unsigned char *der, size_t derlen,
                                  size_t *r_nread, char **r_oid)
{
  KsbaError err;
  int is_bitstr;
  size_t nread, off, len;

  /* fixme: get_algorithm might return the error invalid keyinfo -
     this should be invalid algorithm identifier */
  *r_oid = NULL;
  *r_nread = 0;
  err = get_algorithm (0, der, derlen, &nread, &off, &len, &is_bitstr,
                       NULL, NULL);
  if (err)
    return err;
  *r_nread = nread;
  *r_oid = ksba_oid_to_str (der+off, len);
  return *r_oid? 0 : KSBA_Out_Of_Core;
}

KsbaError
_ksba_parse_algorithm_identifier2 (const unsigned char *der, size_t derlen,
                                   size_t *r_nread, char **r_oid,
                                   char **r_parm, size_t *r_parmlen)
{
  KsbaError err;
  int is_bitstr;
  size_t nread, off, len, off2, len2;

  /* fixme: get_algorithm might return the error invalid keyinfo -
     this should be invalid algorithm identifier */
  *r_oid = NULL;
  *r_nread = 0;
  err = get_algorithm (0, der, derlen, &nread, &off, &len, &is_bitstr,
                       &off2, &len2);
  if (err)
    return err;
  *r_nread = nread;
  *r_oid = ksba_oid_to_str (der+off, len);
  if (!*r_oid)
    return KSBA_Out_Of_Core;
  if (r_parm && r_parmlen)
    {
      *r_parm = xtrymalloc (len2);
      if (!*r_parm)
        {
          xfree (*r_oid); 
          *r_oid = NULL;
          return KSBA_Out_Of_Core;
        }
      memcpy (*r_parm, der+off2, len2);
      *r_parmlen = len2;
    }
  return 0;
}



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
  int c;
  size_t nread, off, len;
  int algoidx;
  int is_bitstr;
  const unsigned char *ctrl;
  const char *elem;
  struct stringbuf sb;

  *r_string = NULL;

  /* check the outer sequence */
  if (!derlen)
    return KSBA_Invalid_Keyinfo;
  c = *der++; derlen--;
  if ( c != 0x30 )
    return KSBA_Unexpected_Tag; /* not a SEQUENCE */
  TLV_LENGTH();
  /* and now the inner part */
  err = get_algorithm (1, der, derlen, &nread, &off, &len, &is_bitstr,
                       NULL, NULL);
  if (err)
    return err;
  
  /* look into our table of supported algorithms */
  for (algoidx=0; pk_algo_table[algoidx].oid; algoidx++)
    {
      if ( len == pk_algo_table[algoidx].oidlen
           && !memcmp (der+off, pk_algo_table[algoidx].oid, len))
        break;
    }
  if (!pk_algo_table[algoidx].oid)
    return KSBA_Unknown_Algorithm;
  if (!pk_algo_table[algoidx].supported)
    return KSBA_Unsupported_Algorithm;

  der += nread;
  derlen -= nread;

  if (is_bitstr)
    { /* Funny: X.509 defines the signature value as a bit string but
         CMS as an octet string - for ease of implementation we always
         allow both */
      if (!derlen)
        return KSBA_Invalid_Keyinfo;
      c = *der++; derlen--;
      if (c) 
        fprintf (stderr, "warning: number of unused bits is not zero\n");
    }

  /* fixme: we should calculate the initial length form the size of the
     sequence, so that we don't neen a realloc later */
  init_stringbuf (&sb, 100);
  put_stringbuf (&sb, "(public-key(");

  /* fixme: we can also use the oidstring here and prefix it with
     "oid." - this way we can pass more information into Libgcrypt or
     whatever library is used */
  put_stringbuf (&sb, pk_algo_table[algoidx].algo_string);

  /* FIXME: We don't release the stringbuf in case of error
     better let the macro jump to a label */
  elem = pk_algo_table[algoidx].elem_string; 
  ctrl = pk_algo_table[algoidx].ctrl_string; 
  for (; *elem; ctrl++, elem++)
    {
      int is_int;

      if (!derlen)
        return KSBA_Invalid_Keyinfo;
      c = *der++; derlen--;
      if ( c != *ctrl )
        return KSBA_Unexpected_Tag; /* not the required tag */
      is_int = c == 0x02;
      TLV_LENGTH ();
      if (is_int && *elem != '-')
        { /* take this integer */
          char tmp[100];
          int i, n;
          
          strcpy (tmp, "(. #"); 
          tmp[1] = *elem;
          put_stringbuf (&sb, tmp);
          for (i=n=0; n < len; n++)
            {
              if (!derlen)
                return KSBA_Invalid_Keyinfo;
              c = *der++; derlen--;
              sprintf (tmp+2*i, "%02X", c);
              if ( !(++i%10) )
                {
                  put_stringbuf (&sb, tmp);
                  i=0;
                }
            }
          if (i)
            put_stringbuf (&sb, tmp);
          put_stringbuf (&sb, "#)");
        }
    }
  put_stringbuf (&sb, "))");
  
  *r_string = get_stringbuf (&sb);
  if (!*r_string)
    return KSBA_Out_Of_Core;

  return 0;
}


/* Mode 0: work as described under _ksba_sigval_to_sexp
   mode 1: work as described under _ksba_encval_to_sexp */
static KsbaError
cryptval_to_sexp (int mode, const unsigned char *der, size_t derlen,
                  char **r_string)
{
  KsbaError err;
  struct algo_table_s *algo_table;
  int c;
  size_t nread, off, len;
  int algoidx;
  int is_bitstr;
  const unsigned char *ctrl;
  const char *elem;
  struct stringbuf sb;

  /* FIXME: The entire function is very similar to keyinfo_to_sexp */
  *r_string = NULL;

  if (!mode)
    algo_table = sig_algo_table;
  else
    algo_table = enc_algo_table;
  

  err = get_algorithm (1, der, derlen, &nread, &off, &len, &is_bitstr,
                       NULL, NULL);
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
    return KSBA_Unknown_Algorithm;
  if (!algo_table[algoidx].supported)
    return KSBA_Unsupported_Algorithm;

  der += nread;
  derlen -= nread;

  if (is_bitstr)
    { /* Funny: X.509 defines the signature value as a bit string but
         CMS as an octet string - for ease of implementation we always
         allow both */
      if (!derlen)
        return KSBA_Invalid_Keyinfo;
      c = *der++; derlen--;
      if (c) 
        fprintf (stderr, "warning: number of unused bits is not zero\n");
    }

  /* fixme: we should calculate the initial length form the size of the
     sequence, so that we don't neen a realloc later */
  init_stringbuf (&sb, 100);
  put_stringbuf (&sb, mode? "(enc-val(":"(sig-val(");
  put_stringbuf (&sb, algo_table[algoidx].algo_string);

  /* FIXME: We don't release the stringbuf in case of error
     better let the macro jump to a label */
  elem = algo_table[algoidx].elem_string; 
  ctrl = algo_table[algoidx].ctrl_string; 
  for (; *elem; ctrl++, elem++)
    {
      int is_int;

      if ( (*ctrl & 0x80) && !elem[1] )
        {  /* Hack to allow a raw value */
          is_int = 1;
          len = derlen;
        }
      else
        {
          if (!derlen)
            return KSBA_Invalid_Keyinfo;
          c = *der++; derlen--;
          if ( c != *ctrl )
            return KSBA_Unexpected_Tag; /* not the required tag */
          is_int = c == 0x02;
          TLV_LENGTH ();
        }
      if (is_int && *elem != '-')
        { /* take this integer */
          char tmp[100];
          int i, n;
          
          strcpy (tmp, "(. #"); 
          tmp[1] = *elem;
          put_stringbuf (&sb, tmp);
          for (i=n=0; n < len; n++)
            {
              if (!derlen)
                return KSBA_Invalid_Keyinfo;
              c = *der++; derlen--;
              sprintf (tmp+2*i, "%02X", c);
              if ( !(++i%10) )
                {
                  put_stringbuf (&sb, tmp);
                  i=0;
                }
            }
          if (i)
            put_stringbuf (&sb, tmp);
          put_stringbuf (&sb, "#)");
        }
    }
  put_stringbuf (&sb, "))");
  
  *r_string = get_stringbuf (&sb);
  if (!*r_string)
    return KSBA_Out_Of_Core;

  return 0;
}

/* Assume that der is a buffer of length DERLEN with a DER encoded
  Asn.1 structure like this:
 
     SEQUENCE { 
        algorithm    OBJECT IDENTIFIER,
        parameters   ANY DEFINED BY algorithm OPTIONAL }
     signature  BIT STRING 
  
  We only allow parameters == NULL.

  The function parses this structure and creates a S-Exp suitable to be
  used as signature value in Libgcrypt:
  
  (sig-val
    (<algo>
      (<param_name1> <mpi>)
      ...
      (<param_namen> <mpi>)
    ))

 The S-Exp will be returned in a string which the caller must free.
 We don't pass an ASN.1 node here but a plain memory block.  */
KsbaError
_ksba_sigval_to_sexp (const unsigned char *der, size_t derlen,
                       char **r_string)
{
  return cryptval_to_sexp (0, der, derlen, r_string);
}


/* Assume that der is a buffer of length DERLEN with a DER encoded
 Asn.1 structure like this:
 
     SEQUENCE { 
        algorithm    OBJECT IDENTIFIER,
        parameters   ANY DEFINED BY algorithm OPTIONAL }
     encryptedKey  OCTET STRING 
  
  We only allow parameters == NULL.

  The function parses this structure and creates a S-Exp suitable to be
  used as encrypted value in Libgcrypt's public key functions:
  
  (enc-val
    (<algo>
      (<param_name1> <mpi>)
      ...
      (<param_namen> <mpi>)
    ))

 The S-Exp will be returned in a string which the caller must free.
 We don't pass an ASN.1 node here but a plain memory block.  */
KsbaError
_ksba_encval_to_sexp (const unsigned char *der, size_t derlen,
                       char **r_string)
{
  return cryptval_to_sexp (1, der, derlen, r_string);
}

