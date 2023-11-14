/* keyinfo.c - Parse and build a keyInfo structure
 * Copyright (C) 2001, 2002, 2007, 2008, 2012, 2020 g10 Code GmbH
 *
 * This file is part of KSBA.
 *
 * KSBA is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * KSBA is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 */

/* Instead of using the ASN parser - which is easily possible - we use
   a simple handcoded one to speed up the operation and to make it
   more robust. */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "asn1-func.h"
#include "keyinfo.h"
#include "shared.h"
#include "convert.h"
#include "ber-help.h"
#include "sexp-parse.h"
#include "stringbuf.h"
#include "der-builder.h"

/* Constants used for the public key algorithms.  */
typedef enum
  {
    PKALGO_NONE,
    PKALGO_RSA,
    PKALGO_DSA,
    PKALGO_ECC,
    PKALGO_X25519,
    PKALGO_X448,
    PKALGO_ED25519,
    PKALGO_ED448
  }
pkalgo_t;


struct algo_table_s {
  const char *oidstring;
  const unsigned char *oid;  /* NULL indicattes end of table */
  int                  oidlen;
  int supported;  /* Values > 1 are also used to indicate hacks.  */
  pkalgo_t pkalgo;
  const char *algo_string;
  const char *elem_string; /* parameter names or '-', 'P' for plain ECDSA */
  const char *ctrl_string; /* expected tag values (value > 127 are raw data)*/
  const char *parmelem_string; /* parameter name or '-'. */
  const char *parmctrl_string; /* expected tag values.  */
  const char *digest_string; /* The digest algo if included in the OID. */
};

/* Special values for the supported field.  */
#define SUPPORTED_RSAPSS 2


static const struct algo_table_s pk_algo_table[] = {

  { /* iso.member-body.us.rsadsi.pkcs.pkcs-1.1 */
    "1.2.840.113549.1.1.1", /* rsaEncryption (RSAES-PKCA1-v1.5) */
    "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", 9,
    1, PKALGO_RSA, "rsa", "-ne", "\x30\x02\x02" },

  { /* iso.member-body.us.rsadsi.pkcs.pkcs-1.7 */
    "1.2.840.113549.1.1.7", /* RSAES-OAEP */
    "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x07", 9,
    0, PKALGO_RSA, "rsa", "-ne", "\x30\x02\x02"},

  { /* iso.member-body.us.rsadsi.pkcs.pkcs-1.10 */
    "1.2.840.113549.1.1.10", /* rsaPSS */
    "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a", 9,
    SUPPORTED_RSAPSS, PKALGO_RSA, "rsa", "-ne", "\x30\x02\x02"},

  { /* */
    "2.5.8.1.1", /* rsa (ambiguous due to missing padding rules)*/
    "\x55\x08\x01\x01", 4,
    1, PKALGO_RSA, "ambiguous-rsa", "-ne", "\x30\x02\x02" },

  { /* iso.member-body.us.x9-57.x9cm.1 */
    "1.2.840.10040.4.1", /*  dsa */
    "\x2a\x86\x48\xce\x38\x04\x01", 7,
    1, PKALGO_DSA, "dsa", "y", "\x02", "-pqg", "\x30\x02\x02\x02" },

  { /* iso.member-body.us.ansi-x9-62.2.1 */
    "1.2.840.10045.2.1", /*  ecPublicKey */
    "\x2a\x86\x48\xce\x3d\x02\x01", 7,
    1, PKALGO_ECC, "ecc", "q", "\x80" },

  { /* iso.identified-organization.thawte.110 */
    "1.3.101.110", /* X25519 */
    "\x2b\x65\x6e", 3,
    1, PKALGO_X25519, "ecc", "q", "\x80" },

  { /* iso.identified-organization.thawte.111 */
    "1.3.101.111", /* X448 */
    "\x2b\x65\x6f", 3,
    1, PKALGO_X448, "ecc", "q", "\x80" },

  { /* iso.identified-organization.thawte.112 */
    "1.3.101.112", /* Ed25519 */
    "\x2b\x65\x70", 3,
    1, PKALGO_ED25519, "ecc", "q", "\x80" },

  { /* iso.identified-organization.thawte.113 */
    "1.3.101.113", /* Ed448 */
    "\x2b\x65\x71", 3,
    1, PKALGO_ED448, "ecc", "q", "\x80" },

  {NULL}
};


static const struct algo_table_s sig_algo_table[] = {
  {  /* iso.member-body.us.rsadsi.pkcs.pkcs-1.5 */
    "1.2.840.113549.1.1.5", /* sha1WithRSAEncryption */
    "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05", 9,
    1, PKALGO_RSA, "rsa", "s", "\x82", NULL, NULL, "sha1" },
  { /* iso.member-body.us.rsadsi.pkcs.pkcs-1.4 */
    "1.2.840.113549.1.1.4", /* md5WithRSAEncryption */
    "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x04", 9,
    1, PKALGO_RSA, "rsa", "s", "\x82", NULL, NULL, "md5" },
  { /* iso.member-body.us.rsadsi.pkcs.pkcs-1.2 */
    "1.2.840.113549.1.1.2", /* md2WithRSAEncryption */
    "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x02", 9,
    0, PKALGO_RSA, "rsa", "s", "\x82", NULL, NULL, "md2" },
  { /* iso.member-body.us.x9-57.x9cm.1 */
    "1.2.840.10040.4.3", /* dsa */
    "\x2a\x86\x48\xce\x38\x04\x01", 7,
    1, PKALGO_DSA, "dsa", "-rs", "\x30\x02\x02" },
  { /* iso.member-body.us.x9-57.x9cm.3 */
    "1.2.840.10040.4.3", /*  dsaWithSha1 */
    "\x2a\x86\x48\xce\x38\x04\x03", 7,
    1, PKALGO_DSA, "dsa", "-rs", "\x30\x02\x02", NULL, NULL, "sha1" },
  { /* Teletrust signature algorithm.  */
    "1.3.36.8.5.1.2.2", /* dsaWithRIPEMD160 */
    "\x2b\x24\x08\x05\x01\x02\x02", 7,
    1, PKALGO_DSA, "dsa", "-rs", "\x30\x02\x02", NULL, NULL, "rmd160" },
  { /* NIST Algorithm */
    "2.16.840.1.101.3.4.3.1", /* dsaWithSha224 */
    "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x01", 11,
    1, PKALGO_DSA, "dsa", "-rs", "\x30\x02\x02", NULL, NULL, "sha224" },
  { /* NIST Algorithm (the draft also used .1 but we better use .2) */
    "2.16.840.1.101.3.4.3.2", /* dsaWithSha256 */
    "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03\x01", 11,
    1, PKALGO_DSA, "dsa", "-rs", "\x30\x02\x02", NULL, NULL, "sha256" },

  { /* iso.member-body.us.ansi-x9-62.signatures.ecdsa-with-sha1 */
    "1.2.840.10045.4.1", /*  ecdsa */
    "\x2a\x86\x48\xce\x3d\x04\x01", 7,
    1, PKALGO_ECC, "ecdsa", "-rs", "\x30\x02\x02", NULL, NULL, "sha1" },

  { /* iso.member-body.us.ansi-x9-62.signatures.ecdsa-with-specified */
    "1.2.840.10045.4.3",
    "\x2a\x86\x48\xce\x3d\x04\x03", 7,
    1, PKALGO_ECC, "ecdsa", "-rs", "\x30\x02\x02", NULL, NULL, NULL },
  /* The digest algorithm is given by the parameter.  */


  { /* iso.member-body.us.ansi-x9-62.signatures.ecdsa-with-sha224 */
    "1.2.840.10045.4.3.1",
    "\x2a\x86\x48\xce\x3d\x04\x03\x01", 8,
    1, PKALGO_ECC, "ecdsa", "-rs", "\x30\x02\x02", NULL, NULL, "sha224" },

  { /* iso.member-body.us.ansi-x9-62.signatures.ecdsa-with-sha256 */
    "1.2.840.10045.4.3.2",
    "\x2a\x86\x48\xce\x3d\x04\x03\x02", 8,
    1, PKALGO_ECC, "ecdsa", "-rs", "\x30\x02\x02", NULL, NULL, "sha256" },

  { /* iso.member-body.us.ansi-x9-62.signatures.ecdsa-with-sha384 */
    "1.2.840.10045.4.3.3",
    "\x2a\x86\x48\xce\x3d\x04\x03\x03", 8,
    1, PKALGO_ECC, "ecdsa", "-rs", "\x30\x02\x02", NULL, NULL, "sha384" },

  { /* iso.member-body.us.ansi-x9-62.signatures.ecdsa-with-sha512 */
    "1.2.840.10045.4.3.4",
    "\x2a\x86\x48\xce\x3d\x04\x03\x04", 8,
    1, PKALGO_ECC, "ecdsa", "-rs", "\x30\x02\x02", NULL, NULL, "sha512" },

  { /* BSI TR-03111 bsiEcdsaWithSHA1 */
    "0.4.0.127.0.7.1.1.4.1.1",
    "\x04\x00\x7f\x00\x07\x01\x01\x04\x01\x01", 10,
    1, PKALGO_ECC, "ecdsa", "P", "", NULL, NULL, "sha1" },

  { /* BSI TR-03111 bsiEcdsaWithSHA224 */
    "0.4.0.127.0.7.1.1.4.1.2",
    "\x04\x00\x7f\x00\x07\x01\x01\x04\x01\x02", 10,
    1, PKALGO_ECC, "ecdsa", "P", "", NULL, NULL, "sha224" },

  { /* BSI TR-03111 bsiEcdsaWithSHA256 */
    "0.4.0.127.0.7.1.1.4.1.3",
    "\x04\x00\x7f\x00\x07\x01\x01\x04\x01\x03", 10,
    1, PKALGO_ECC, "ecdsa", "P", "", NULL, NULL, "sha256" },

  { /* BSI TR-03111 bsiEcdsaWithSHA384 */
    "0.4.0.127.0.7.1.1.4.1.4",
    "\x04\x00\x7f\x00\x07\x01\x01\x04\x01\x04", 10,
    1, PKALGO_ECC, "ecdsa", "P", "", NULL, NULL, "sha384" },

  { /* BSI TR-03111 bsiEcdsaWithSHA512 */
    "0.4.0.127.0.7.1.1.4.1.5",
    "\x04\x00\x7f\x00\x07\x01\x01\x04\x01\x05", 10,
    1, PKALGO_ECC, "ecdsa", "P", "", NULL, NULL, "sha512" },

  { /* iso.member-body.us.rsadsi.pkcs.pkcs-1.1 */
    "1.2.840.113549.1.1.1", /* rsaEncryption used without hash algo*/
    "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", 9,
    1, PKALGO_RSA, "rsa", "s", "\x82" },
  { /* from NIST's OIW - actually belongs in a pure hash table */
    "1.3.14.3.2.26",  /* sha1 */
    "\x2B\x0E\x03\x02\x1A", 5,
    0, PKALGO_RSA, "sha-1", "", "", NULL, NULL, "sha1" },

  { /* As used by telesec cards */
    "1.3.36.3.3.1.2",  /* rsaSignatureWithripemd160 */
    "\x2b\x24\x03\x03\x01\x02", 6,
    1, PKALGO_RSA, "rsa", "s", "\x82", NULL, NULL, "rmd160" },

  { /* from NIST's OIW - used by TU Darmstadt */
    "1.3.14.3.2.29",  /* sha-1WithRSAEncryption */
    "\x2B\x0E\x03\x02\x1D", 5,
    1, PKALGO_RSA, "rsa", "s", "\x82", NULL, NULL, "sha1" },

  { /* from PKCS#1  */
    "1.2.840.113549.1.1.11", /* sha256WithRSAEncryption */
    "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b", 9,
    1, PKALGO_RSA, "rsa", "s", "\x82", NULL, NULL, "sha256" },

  { /* from PKCS#1  */
    "1.2.840.113549.1.1.12", /* sha384WithRSAEncryption */
    "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c", 9,
    1, PKALGO_RSA, "rsa", "s", "\x82", NULL, NULL, "sha384" },

  { /* from PKCS#1  */
    "1.2.840.113549.1.1.13", /* sha512WithRSAEncryption */
    "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d", 9,
    1, PKALGO_RSA, "rsa", "s", "\x82", NULL, NULL, "sha512" },

  { /* iso.member-body.us.rsadsi.pkcs.pkcs-1.10 */
    "1.2.840.113549.1.1.10", /* rsaPSS */
    "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a", 9,
    SUPPORTED_RSAPSS, PKALGO_RSA, "rsa", "s", "\x82", NULL, NULL, NULL},

  { /* TeleTrust signature scheme with RSA signature and DSI according
       to ISO/IEC 9796-2 with random number and RIPEMD-160.  I am not
       sure for what this is good; thus disabled. */
    "1.3.36.3.4.3.2.2",     /* sigS_ISO9796-2rndWithrsa_ripemd160 */
    "\x2B\x24\x03\x04\x03\x02\x02", 7,
    0, PKALGO_RSA, "rsa", "s", "\x82", NULL, NULL, "rmd160" },


  { /* iso.identified-organization.thawte.112 */
    "1.3.101.112", /* Ed25519 */
    "\x2b\x65\x70", 3,
    1, PKALGO_ED25519, "eddsa", "", "", NULL, NULL, NULL },
  { /* iso.identified-organization.thawte.113 */
    "1.3.101.113", /* Ed448 */
    "\x2b\x65\x71", 3,
    1, PKALGO_ED448, "eddsa", "", "", NULL, NULL, NULL },

  {NULL}
};

static const struct algo_table_s enc_algo_table[] = {
  {/* iso.member-body.us.rsadsi.pkcs.pkcs-1.1 */
   "1.2.840.113549.1.1.1", /* rsaEncryption (RSAES-PKCA1-v1.5) */
   "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01", 9,
   1, PKALGO_RSA, "rsa", "a", "\x82" },
  {/* iso.member-body.us.ansi-x9-62.2.1 */
   "1.2.840.10045.2.1", /* ecPublicKey */
   "\x2a\x86\x48\xce\x3d\x02\x01", 7,
   1, PKALGO_ECC, "ecdh", "e", "\x80" },
  {NULL}
};


/* This tables maps names of ECC curves names to OIDs.  A similar
   table is used by Libgcrypt.  */
static const struct
{
  const char *oid;
  const char *name;
  unsigned char pkalgo;  /* If not 0 force the use of ALGO.  */
} curve_names[] =
  {
    { "1.3.101.112",         "Ed25519",    PKALGO_ED25519},
    { "1.3.101.110",         "Curve25519", PKALGO_X25519},
    { "1.3.101.110",         "X25519",     PKALGO_X25519},

    { "1.3.101.113",         "Ed448",      PKALGO_ED448 },
    { "1.3.101.111",         "X448",       PKALGO_X448  },

    { "1.2.840.10045.3.1.1", "NIST P-192" },
    { "1.2.840.10045.3.1.1", "nistp192"   },
    { "1.2.840.10045.3.1.1", "prime192v1" },
    { "1.2.840.10045.3.1.1", "secp192r1"  },

    { "1.3.132.0.33",        "NIST P-224" },
    { "1.3.132.0.33",        "nistp224"   },
    { "1.3.132.0.33",        "secp224r1"  },

    { "1.2.840.10045.3.1.7", "NIST P-256" },
    { "1.2.840.10045.3.1.7", "nistp256"   },
    { "1.2.840.10045.3.1.7", "prime256v1" },
    { "1.2.840.10045.3.1.7", "secp256r1"  },

    { "1.3.132.0.34",        "NIST P-384" },
    { "1.3.132.0.34",        "nistp384"   },
    { "1.3.132.0.34",        "secp384r1"  },

    { "1.3.132.0.35",        "NIST P-521" },
    { "1.3.132.0.35",        "nistp521"   },
    { "1.3.132.0.35",        "secp521r1"  },

    { "1.3.36.3.3.2.8.1.1.1" , "brainpoolP160r1" },
    { "1.3.36.3.3.2.8.1.1.3" , "brainpoolP192r1" },
    { "1.3.36.3.3.2.8.1.1.5" , "brainpoolP224r1" },
    { "1.3.36.3.3.2.8.1.1.7" , "brainpoolP256r1" },
    { "1.3.36.3.3.2.8.1.1.9" , "brainpoolP320r1" },
    { "1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1" },
    { "1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1" },


    { "1.2.643.2.2.35.1",    "GOST2001-CryptoPro-A" },
    { "1.2.643.2.2.35.2",    "GOST2001-CryptoPro-B" },
    { "1.2.643.2.2.35.3",    "GOST2001-CryptoPro-C" },
    { "1.2.643.7.1.2.1.2.1", "GOST2012-tc26-A"      },
    { "1.2.643.7.1.2.1.2.2", "GOST2012-tc26-B"      },

    { "1.3.132.0.10",        "secp256k1" },

    { NULL, NULL}
  };


/* Table to map well known curve parameters to their name.  */
static const struct
{
  const char *name;
  unsigned int derlen;
  const unsigned char *der;
} ecdomainparm_to_name[] =
  {
    { "brainpoolP256r1", 227,
      "\x30\x81\xe0\x02\x01\x01\x30\x2c\x06\x07\x2a\x86\x48\xce\x3d\x01"
      "\x01\x02\x21\x00\xa9\xfb\x57\xdb\xa1\xee\xa9\xbc\x3e\x66\x0a\x90"
      "\x9d\x83\x8d\x72\x6e\x3b\xf6\x23\xd5\x26\x20\x28\x20\x13\x48\x1d"
      "\x1f\x6e\x53\x77\x30\x44\x04\x20\x7d\x5a\x09\x75\xfc\x2c\x30\x57"
      "\xee\xf6\x75\x30\x41\x7a\xff\xe7\xfb\x80\x55\xc1\x26\xdc\x5c\x6c"
      "\xe9\x4a\x4b\x44\xf3\x30\xb5\xd9\x04\x20\x26\xdc\x5c\x6c\xe9\x4a"
      "\x4b\x44\xf3\x30\xb5\xd9\xbb\xd7\x7c\xbf\x95\x84\x16\x29\x5c\xf7"
      "\xe1\xce\x6b\xcc\xdc\x18\xff\x8c\x07\xb6\x04\x41\x04\x8b\xd2\xae"
      "\xb9\xcb\x7e\x57\xcb\x2c\x4b\x48\x2f\xfc\x81\xb7\xaf\xb9\xde\x27"
      "\xe1\xe3\xbd\x23\xc2\x3a\x44\x53\xbd\x9a\xce\x32\x62\x54\x7e\xf8"
      "\x35\xc3\xda\xc4\xfd\x97\xf8\x46\x1a\x14\x61\x1d\xc9\xc2\x77\x45"
      "\x13\x2d\xed\x8e\x54\x5c\x1d\x54\xc7\x2f\x04\x69\x97\x02\x21\x00"
      "\xa9\xfb\x57\xdb\xa1\xee\xa9\xbc\x3e\x66\x0a\x90\x9d\x83\x8d\x71"
      "\x8c\x39\x7a\xa3\xb5\x61\xa6\xf7\x90\x1e\x0e\x82\x97\x48\x56\xa7"
      "\x02\x01\x01"
    },

    { "brainpoolP384r1", 324,
      "\x30\x82\x01\x40\x02\x01\x01\x30\x3c\x06\x07\x2a\x86\x48\xce\x3d"
      "\x01\x01\x02\x31\x00\x8c\xb9\x1e\x82\xa3\x38\x6d\x28\x0f\x5d\x6f"
      "\x7e\x50\xe6\x41\xdf\x15\x2f\x71\x09\xed\x54\x56\xb4\x12\xb1\xda"
      "\x19\x7f\xb7\x11\x23\xac\xd3\xa7\x29\x90\x1d\x1a\x71\x87\x47\x00"
      "\x13\x31\x07\xec\x53\x30\x64\x04\x30\x7b\xc3\x82\xc6\x3d\x8c\x15"
      "\x0c\x3c\x72\x08\x0a\xce\x05\xaf\xa0\xc2\xbe\xa2\x8e\x4f\xb2\x27"
      "\x87\x13\x91\x65\xef\xba\x91\xf9\x0f\x8a\xa5\x81\x4a\x50\x3a\xd4"
      "\xeb\x04\xa8\xc7\xdd\x22\xce\x28\x26\x04\x30\x04\xa8\xc7\xdd\x22"
      "\xce\x28\x26\x8b\x39\xb5\x54\x16\xf0\x44\x7c\x2f\xb7\x7d\xe1\x07"
      "\xdc\xd2\xa6\x2e\x88\x0e\xa5\x3e\xeb\x62\xd5\x7c\xb4\x39\x02\x95"
      "\xdb\xc9\x94\x3a\xb7\x86\x96\xfa\x50\x4c\x11\x04\x61\x04\x1d\x1c"
      "\x64\xf0\x68\xcf\x45\xff\xa2\xa6\x3a\x81\xb7\xc1\x3f\x6b\x88\x47"
      "\xa3\xe7\x7e\xf1\x4f\xe3\xdb\x7f\xca\xfe\x0c\xbd\x10\xe8\xe8\x26"
      "\xe0\x34\x36\xd6\x46\xaa\xef\x87\xb2\xe2\x47\xd4\xaf\x1e\x8a\xbe"
      "\x1d\x75\x20\xf9\xc2\xa4\x5c\xb1\xeb\x8e\x95\xcf\xd5\x52\x62\xb7"
      "\x0b\x29\xfe\xec\x58\x64\xe1\x9c\x05\x4f\xf9\x91\x29\x28\x0e\x46"
      "\x46\x21\x77\x91\x81\x11\x42\x82\x03\x41\x26\x3c\x53\x15\x02\x31"
      "\x00\x8c\xb9\x1e\x82\xa3\x38\x6d\x28\x0f\x5d\x6f\x7e\x50\xe6\x41"
      "\xdf\x15\x2f\x71\x09\xed\x54\x56\xb3\x1f\x16\x6e\x6c\xac\x04\x25"
      "\xa7\xcf\x3a\xb6\xaf\x6b\x7f\xc3\x10\x3b\x88\x32\x02\xe9\x04\x65"
      "\x65\x02\x01\x01"
    },

    { "brainpoolP512r1", 422,
      "\x30\x82\x01\xa2\x02\x01\x01\x30\x4c\x06\x07\x2a\x86\x48\xce\x3d"
      "\x01\x01\x02\x41\x00\xaa\xdd\x9d\xb8\xdb\xe9\xc4\x8b\x3f\xd4\xe6"
      "\xae\x33\xc9\xfc\x07\xcb\x30\x8d\xb3\xb3\xc9\xd2\x0e\xd6\x63\x9c"
      "\xca\x70\x33\x08\x71\x7d\x4d\x9b\x00\x9b\xc6\x68\x42\xae\xcd\xa1"
      "\x2a\xe6\xa3\x80\xe6\x28\x81\xff\x2f\x2d\x82\xc6\x85\x28\xaa\x60"
      "\x56\x58\x3a\x48\xf3\x30\x81\x84\x04\x40\x78\x30\xa3\x31\x8b\x60"
      "\x3b\x89\xe2\x32\x71\x45\xac\x23\x4c\xc5\x94\xcb\xdd\x8d\x3d\xf9"
      "\x16\x10\xa8\x34\x41\xca\xea\x98\x63\xbc\x2d\xed\x5d\x5a\xa8\x25"
      "\x3a\xa1\x0a\x2e\xf1\xc9\x8b\x9a\xc8\xb5\x7f\x11\x17\xa7\x2b\xf2"
      "\xc7\xb9\xe7\xc1\xac\x4d\x77\xfc\x94\xca\x04\x40\x3d\xf9\x16\x10"
      "\xa8\x34\x41\xca\xea\x98\x63\xbc\x2d\xed\x5d\x5a\xa8\x25\x3a\xa1"
      "\x0a\x2e\xf1\xc9\x8b\x9a\xc8\xb5\x7f\x11\x17\xa7\x2b\xf2\xc7\xb9"
      "\xe7\xc1\xac\x4d\x77\xfc\x94\xca\xdc\x08\x3e\x67\x98\x40\x50\xb7"
      "\x5e\xba\xe5\xdd\x28\x09\xbd\x63\x80\x16\xf7\x23\x04\x81\x81\x04"
      "\x81\xae\xe4\xbd\xd8\x2e\xd9\x64\x5a\x21\x32\x2e\x9c\x4c\x6a\x93"
      "\x85\xed\x9f\x70\xb5\xd9\x16\xc1\xb4\x3b\x62\xee\xf4\xd0\x09\x8e"
      "\xff\x3b\x1f\x78\xe2\xd0\xd4\x8d\x50\xd1\x68\x7b\x93\xb9\x7d\x5f"
      "\x7c\x6d\x50\x47\x40\x6a\x5e\x68\x8b\x35\x22\x09\xbc\xb9\xf8\x22"
      "\x7d\xde\x38\x5d\x56\x63\x32\xec\xc0\xea\xbf\xa9\xcf\x78\x22\xfd"
      "\xf2\x09\xf7\x00\x24\xa5\x7b\x1a\xa0\x00\xc5\x5b\x88\x1f\x81\x11"
      "\xb2\xdc\xde\x49\x4a\x5f\x48\x5e\x5b\xca\x4b\xd8\x8a\x27\x63\xae"
      "\xd1\xca\x2b\x2f\xa8\xf0\x54\x06\x78\xcd\x1e\x0f\x3a\xd8\x08\x92"
      "\x02\x41\x00\xaa\xdd\x9d\xb8\xdb\xe9\xc4\x8b\x3f\xd4\xe6\xae\x33"
      "\xc9\xfc\x07\xcb\x30\x8d\xb3\xb3\xc9\xd2\x0e\xd6\x63\x9c\xca\x70"
      "\x33\x08\x70\x55\x3e\x5c\x41\x4c\xa9\x26\x19\x41\x86\x61\x19\x7f"
      "\xac\x10\x47\x1d\xb1\xd3\x81\x08\x5d\xda\xdd\xb5\x87\x96\x82\x9c"
      "\xa9\x00\x69\x02\x01\x01"
    },

    { "brainpoolP256r1", 195, /* with compressed base point */
      "\x30\x81\xc0\x02\x01\x01\x30\x2c\x06\x07\x2a\x86\x48\xce\x3d\x01"
      "\x01\x02\x21\x00\xa9\xfb\x57\xdb\xa1\xee\xa9\xbc\x3e\x66\x0a\x90"
      "\x9d\x83\x8d\x72\x6e\x3b\xf6\x23\xd5\x26\x20\x28\x20\x13\x48\x1d"
      "\x1f\x6e\x53\x77\x30\x44\x04\x20\x7d\x5a\x09\x75\xfc\x2c\x30\x57"
      "\xee\xf6\x75\x30\x41\x7a\xff\xe7\xfb\x80\x55\xc1\x26\xdc\x5c\x6c"
      "\xe9\x4a\x4b\x44\xf3\x30\xb5\xd9\x04\x20\x26\xdc\x5c\x6c\xe9\x4a"
      "\x4b\x44\xf3\x30\xb5\xd9\xbb\xd7\x7c\xbf\x95\x84\x16\x29\x5c\xf7"
      "\xe1\xce\x6b\xcc\xdc\x18\xff\x8c\x07\xb6\x04\x21\x03\x8b\xd2\xae"
      "\xb9\xcb\x7e\x57\xcb\x2c\x4b\x48\x2f\xfc\x81\xb7\xaf\xb9\xde\x27"
      "\xe1\xe3\xbd\x23\xc2\x3a\x44\x53\xbd\x9a\xce\x32\x62\x02\x21\x00"
      "\xa9\xfb\x57\xdb\xa1\xee\xa9\xbc\x3e\x66\x0a\x90\x9d\x83\x8d\x71"
      "\x8c\x39\x7a\xa3\xb5\x61\xa6\xf7\x90\x1e\x0e\x82\x97\x48\x56\xa7"
      "\x02\x01\x01"
    },

    { "brainpoolP384r1", 276, /* with compressed base point */
      "\x30\x82\x01\x10\x02\x01\x01\x30\x3c\x06\x07\x2a\x86\x48\xce\x3d"
      "\x01\x01\x02\x31\x00\x8c\xb9\x1e\x82\xa3\x38\x6d\x28\x0f\x5d\x6f"
      "\x7e\x50\xe6\x41\xdf\x15\x2f\x71\x09\xed\x54\x56\xb4\x12\xb1\xda"
      "\x19\x7f\xb7\x11\x23\xac\xd3\xa7\x29\x90\x1d\x1a\x71\x87\x47\x00"
      "\x13\x31\x07\xec\x53\x30\x64\x04\x30\x7b\xc3\x82\xc6\x3d\x8c\x15"
      "\x0c\x3c\x72\x08\x0a\xce\x05\xaf\xa0\xc2\xbe\xa2\x8e\x4f\xb2\x27"
      "\x87\x13\x91\x65\xef\xba\x91\xf9\x0f\x8a\xa5\x81\x4a\x50\x3a\xd4"
      "\xeb\x04\xa8\xc7\xdd\x22\xce\x28\x26\x04\x30\x04\xa8\xc7\xdd\x22"
      "\xce\x28\x26\x8b\x39\xb5\x54\x16\xf0\x44\x7c\x2f\xb7\x7d\xe1\x07"
      "\xdc\xd2\xa6\x2e\x88\x0e\xa5\x3e\xeb\x62\xd5\x7c\xb4\x39\x02\x95"
      "\xdb\xc9\x94\x3a\xb7\x86\x96\xfa\x50\x4c\x11\x04\x31\x03\x1d\x1c"
      "\x64\xf0\x68\xcf\x45\xff\xa2\xa6\x3a\x81\xb7\xc1\x3f\x6b\x88\x47"
      "\xa3\xe7\x7e\xf1\x4f\xe3\xdb\x7f\xca\xfe\x0c\xbd\x10\xe8\xe8\x26"
      "\xe0\x34\x36\xd6\x46\xaa\xef\x87\xb2\xe2\x47\xd4\xaf\x1e\x02\x31"
      "\x00\x8c\xb9\x1e\x82\xa3\x38\x6d\x28\x0f\x5d\x6f\x7e\x50\xe6\x41"
      "\xdf\x15\x2f\x71\x09\xed\x54\x56\xb3\x1f\x16\x6e\x6c\xac\x04\x25"
      "\xa7\xcf\x3a\xb6\xaf\x6b\x7f\xc3\x10\x3b\x88\x32\x02\xe9\x04\x65"
      "\x65\x02\x01\x01"
    },

    { "brainpoolP512r1", 357,  /* with compressed base point */
      "\x30\x82\x01\x61\x02\x01\x01\x30\x4c\x06\x07\x2a\x86\x48\xce\x3d"
      "\x01\x01\x02\x41\x00\xaa\xdd\x9d\xb8\xdb\xe9\xc4\x8b\x3f\xd4\xe6"
      "\xae\x33\xc9\xfc\x07\xcb\x30\x8d\xb3\xb3\xc9\xd2\x0e\xd6\x63\x9c"
      "\xca\x70\x33\x08\x71\x7d\x4d\x9b\x00\x9b\xc6\x68\x42\xae\xcd\xa1"
      "\x2a\xe6\xa3\x80\xe6\x28\x81\xff\x2f\x2d\x82\xc6\x85\x28\xaa\x60"
      "\x56\x58\x3a\x48\xf3\x30\x81\x84\x04\x40\x78\x30\xa3\x31\x8b\x60"
      "\x3b\x89\xe2\x32\x71\x45\xac\x23\x4c\xc5\x94\xcb\xdd\x8d\x3d\xf9"
      "\x16\x10\xa8\x34\x41\xca\xea\x98\x63\xbc\x2d\xed\x5d\x5a\xa8\x25"
      "\x3a\xa1\x0a\x2e\xf1\xc9\x8b\x9a\xc8\xb5\x7f\x11\x17\xa7\x2b\xf2"
      "\xc7\xb9\xe7\xc1\xac\x4d\x77\xfc\x94\xca\x04\x40\x3d\xf9\x16\x10"
      "\xa8\x34\x41\xca\xea\x98\x63\xbc\x2d\xed\x5d\x5a\xa8\x25\x3a\xa1"
      "\x0a\x2e\xf1\xc9\x8b\x9a\xc8\xb5\x7f\x11\x17\xa7\x2b\xf2\xc7\xb9"
      "\xe7\xc1\xac\x4d\x77\xfc\x94\xca\xdc\x08\x3e\x67\x98\x40\x50\xb7"
      "\x5e\xba\xe5\xdd\x28\x09\xbd\x63\x80\x16\xf7\x23\x04\x41\x02\x81"
      "\xae\xe4\xbd\xd8\x2e\xd9\x64\x5a\x21\x32\x2e\x9c\x4c\x6a\x93\x85"
      "\xed\x9f\x70\xb5\xd9\x16\xc1\xb4\x3b\x62\xee\xf4\xd0\x09\x8e\xff"
      "\x3b\x1f\x78\xe2\xd0\xd4\x8d\x50\xd1\x68\x7b\x93\xb9\x7d\x5f\x7c"
      "\x6d\x50\x47\x40\x6a\x5e\x68\x8b\x35\x22\x09\xbc\xb9\xf8\x22\x02"
      "\x41\x00\xaa\xdd\x9d\xb8\xdb\xe9\xc4\x8b\x3f\xd4\xe6\xae\x33\xc9"
      "\xfc\x07\xcb\x30\x8d\xb3\xb3\xc9\xd2\x0e\xd6\x63\x9c\xca\x70\x33"
      "\x08\x70\x55\x3e\x5c\x41\x4c\xa9\x26\x19\x41\x86\x61\x19\x7f\xac"
      "\x10\x47\x1d\xb1\xd3\x81\x08\x5d\xda\xdd\xb5\x87\x96\x82\x9c\xa9"
      "\x00\x69\x02\x01\x01"
    },

    { NULL }
  };


#define TLV_LENGTH(prefix) do {         \
  if (!prefix ## len)                    \
    return gpg_error (GPG_ERR_INV_KEYINFO);  \
  c = *(prefix)++; prefix ## len--;           \
  if (c == 0x80)                  \
    return gpg_error (GPG_ERR_NOT_DER_ENCODED);  \
  if (c == 0xff)                  \
    return gpg_error (GPG_ERR_BAD_BER);        \
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
          if (!prefix ## len)            \
            return gpg_error (GPG_ERR_BAD_BER);\
          c = *(prefix)++; prefix ## len--;   \
          len |= c & 0xff;        \
        }                         \
    }                             \
  if (len > prefix ## len)               \
    return gpg_error (GPG_ERR_INV_KEYINFO);  \
} while (0)


/* Given a string BUF of length BUFLEN with either a curve name or its
 * OID in dotted form return a string in dotted form of the name.  The
 * caller must free the result.  On error NULL is returned.  If a
 * curve requires the use of a certain algorithm, that algorithm is
 * stored at R_PKALGO.  */
static char *
get_ecc_curve_oid (const unsigned char *buf, size_t buflen, pkalgo_t *r_pkalgo)
{
  unsigned char *result;
  int i, find_pkalgo;

  /* Skip an optional "oid." prefix. */
  if (buflen > 4 && buf[3] == '.' && digitp (buf+4)
      && ((buf[0] == 'o' && buf[1] == 'i' && buf[2] == 'd')
          ||(buf[0] == 'O' && buf[1] == 'I' && buf[2] == 'D')))
    {
      buf += 4;
      buflen -= 4;
    }

  /* If it does not look like an OID - map it through the table.  */
  if (buflen && !digitp (buf))
    {
      for (i=0; curve_names[i].oid; i++)
        if (buflen == strlen (curve_names[i].name)
            && !memcmp (buf, curve_names[i].name, buflen))
          break;
      if (!curve_names[i].oid)
        return NULL; /* Not found.  */
      buf = curve_names[i].oid;
      buflen = strlen (curve_names[i].oid);
      *r_pkalgo = curve_names[i].pkalgo;
      find_pkalgo = 0;
    }
  else
    find_pkalgo = 1;

  result = xtrymalloc (buflen + 1);
  if (!result)
    return NULL; /* Ooops */
  memcpy (result, buf, buflen);
  result[buflen] = 0;

  if (find_pkalgo)
    {
      /* We still need to check whether the OID requires a certain ALGO.  */
      for (i=0; curve_names[i].oid; i++)
        if (!strcmp (curve_names[i].oid, result))
          {
            *r_pkalgo = curve_names[i].pkalgo;
            break;
          }
    }

  return result;
}



/* Return the OFF and the LEN of algorithm within DER.  Do some checks
   and return the number of bytes read in r_nread, adding this to der
   does point into the BIT STRING.

   mode 0: just get the algorithm identifier. FIXME: should be able to
           handle BER Encoding.
   mode 1: as described.
 */
static gpg_error_t
get_algorithm (int mode, const unsigned char *der, size_t derlen, int firsttag,
               size_t *r_nread, size_t *r_pos, size_t *r_len, int *r_bitstr,
               size_t *r_parm_pos, size_t *r_parm_len, int *r_parm_type)
{
  int c;
  const unsigned char *start = der;
  const unsigned char *startseq;
  unsigned long seqlen, len;

  *r_bitstr = 0;
  if (r_parm_pos)
    *r_parm_pos = 0;
  if (r_parm_len)
    *r_parm_len = 0;
  if (r_parm_type)
    *r_parm_type = 0;
  /* get the inner sequence */
  if (!derlen)
    return gpg_error (GPG_ERR_INV_KEYINFO);
  c = *der++; derlen--;
  if ( c != firsttag )
    return gpg_error (GPG_ERR_UNEXPECTED_TAG); /* not a SEQUENCE  or whatever */
  TLV_LENGTH(der);
  seqlen = len;
  startseq = der;

  /* get the object identifier */
  if (!derlen)
    return gpg_error (GPG_ERR_INV_KEYINFO);
  c = *der++; derlen--;
  if ( c != 0x06 )
    return gpg_error (GPG_ERR_UNEXPECTED_TAG); /* not an OBJECT IDENTIFIER */
  TLV_LENGTH(der);

  /* der does now point to an oid of length LEN */
  *r_pos = der - start;
  *r_len = len;
  der += len;
  derlen -= len;
  seqlen -= der - startseq;;

  /* Parse the parameter.  */
  if (seqlen)
    {
      const unsigned char *startparm = der;

      if (!derlen)
        return gpg_error (GPG_ERR_INV_KEYINFO);
      c = *der++; derlen--;
      if ( c == 0x05 )
        {
          /* gpgrt_log_debug ("%s: parameter: NULL \n", __func__); */
          if (!derlen)
            return gpg_error (GPG_ERR_INV_KEYINFO);
          c = *der++; derlen--;
          if (c)
            return gpg_error (GPG_ERR_BAD_BER);  /* NULL must have a
                                                    length of 0 */
          seqlen -= 2;
        }
      else if (r_parm_pos && r_parm_len && c == 0x04)
        {
          /*  This is an octet string parameter and we need it.  */
          if (r_parm_type)
            *r_parm_type = TYPE_OCTET_STRING;
          TLV_LENGTH(der);
          *r_parm_pos = der - start;
          *r_parm_len = len;
          seqlen -= der - startparm;
          der += len;
          derlen -= len;
          seqlen -= len;
        }
      else if (r_parm_pos && r_parm_len && c == 0x06)
        {
          /*  This is an object identifier.  */
          if (r_parm_type)
            *r_parm_type = TYPE_OBJECT_ID;
          TLV_LENGTH(der);
          *r_parm_pos = der - start;
          *r_parm_len = len;
          seqlen -= der - startparm;
          der += len;
          derlen -= len;
          seqlen -= len;
        }
      else if (r_parm_pos && r_parm_len && c == 0x30)
        {
          /*  This is a sequence. */
          if (r_parm_type)
            *r_parm_type = TYPE_SEQUENCE;
          TLV_LENGTH(der);
          *r_parm_pos = startparm - start;
          *r_parm_len = len + (der - startparm);
          seqlen -= der - startparm;
          der += len;
          derlen -= len;
          seqlen -= len;
        }
      else
        {
/*            printf ("parameter: with tag %02x - ignored\n", c); */
          TLV_LENGTH(der);
          seqlen -= der - startparm;
          /* skip the value */
          der += len;
          derlen -= len;
          seqlen -= len;
        }
    }

  if (seqlen)
    return gpg_error (GPG_ERR_INV_KEYINFO);

  if (mode)
    {
      /* move forward to the BIT_STR */
      if (!derlen)
        return gpg_error (GPG_ERR_INV_KEYINFO);
      c = *der++; derlen--;

      if (c == 0x03)
        *r_bitstr = 1; /* BIT STRING */
      else if (c == 0x04)
        ; /* OCTECT STRING */
      else
        return gpg_error (GPG_ERR_UNEXPECTED_TAG); /* not a BIT STRING */
      TLV_LENGTH(der);
    }

  *r_nread = der - start;
  return 0;
}


gpg_error_t
_ksba_parse_algorithm_identifier (const unsigned char *der, size_t derlen,
                                  size_t *r_nread, char **r_oid)
{
  return _ksba_parse_algorithm_identifier3 (der, derlen, 0x30,
                                            r_nread, r_oid, NULL, NULL, NULL);
}


gpg_error_t
_ksba_parse_algorithm_identifier2 (const unsigned char *der, size_t derlen,
                                   size_t *r_nread, char **r_oid,
                                   char **r_parm, size_t *r_parmlen)
{
  return _ksba_parse_algorithm_identifier3 (der, derlen, 0x30,
                                            r_nread, r_oid,
                                            r_parm, r_parmlen, NULL);
}


/* Note that R_NREAD, R_PARM, and R_PARMLEN are optional.  */
gpg_error_t
_ksba_parse_algorithm_identifier3 (const unsigned char *der, size_t derlen,
                                   int firsttag,
                                   size_t *r_nread, char **r_oid,
                                   char **r_parm, size_t *r_parmlen,
                                   int *r_parmtype)
{
  gpg_error_t err;
  int is_bitstr;
  size_t nread, off, len, off2, len2;
  int parm_type;

  /* fixme: get_algorithm might return the error invalid keyinfo -
     this should be invalid algorithm identifier */
  *r_oid = NULL;
  if (r_nread)
    *r_nread = 0;
  off2 = len2 = 0;
  err = get_algorithm (0, der, derlen, firsttag,
                       &nread, &off, &len, &is_bitstr,
                       &off2, &len2, &parm_type);
  if (err)
    return err;
  if (r_nread)
    *r_nread = nread;
  *r_oid = ksba_oid_to_str (der+off, len);
  if (!*r_oid)
    return gpg_error (GPG_ERR_ENOMEM);

  /* Special hack for ecdsaWithSpecified.  We replace the returned OID
     by the one in the parameter. */
  if (off2 && len2 && parm_type == TYPE_SEQUENCE && firsttag == 0x30
      && !strcmp (*r_oid, "1.2.840.10045.4.3"))
    {
      xfree (*r_oid);
      *r_oid = NULL;
      err = get_algorithm (0, der+off2, len2, 0x30,
                           &nread, &off, &len, &is_bitstr,
                           NULL, NULL, NULL);
      if (err)
        {
          if (r_nread)
            *r_nread = 0;
          return err;
        }
      *r_oid = ksba_oid_to_str (der+off2+off, len);
      if (!*r_oid)
        {
          if (r_nread)
            *r_nread = 0;
          return gpg_error (GPG_ERR_ENOMEM);
        }

      off2 = len2 = 0; /* So that R_PARM is set to NULL.  */
    }

  if (r_parm && r_parmlen)
    {
      if (off2 && len2)
        {
          *r_parm = xtrymalloc (len2);
          if (!*r_parm)
            {
              xfree (*r_oid);
              *r_oid = NULL;
              return gpg_error (GPG_ERR_ENOMEM);
            }
          memcpy (*r_parm, der+off2, len2);
          *r_parmlen = len2;
        }
      else
        {
          *r_parm = NULL;
          *r_parmlen = 0;
        }
    }
  if (r_parmtype)
    *r_parmtype = parm_type;

  return 0;
}


/* Assume that DER is a buffer of length DERLEN with a DER encoded
   ASN.1 structure like this:

  keyInfo ::= SEQUENCE {
                 SEQUENCE {
                    algorithm    OBJECT IDENTIFIER,
                    parameters   ANY DEFINED BY algorithm OPTIONAL }
                 publicKey  BIT STRING }

  The function parses this structure and create a SEXP suitable to be
  used as a public key in Libgcrypt.  The S-Exp will be returned in a
  string which the caller must free.

  We don't pass an ASN.1 node here but a plain memory block.  */

gpg_error_t
_ksba_keyinfo_to_sexp (const unsigned char *der, size_t derlen,
                       ksba_sexp_t *r_string)
{
  gpg_error_t err;
  int c, i;
  size_t nread, off, len, parm_off, parm_len;
  int parm_type;
  char *parm_oid = NULL;
  int algoidx;
  int is_bitstr;
  int got_curve = 0;
  const unsigned char *parmder = NULL;
  size_t parmderlen = 0;
  const unsigned char *ctrl;
  const char *elem;
  struct stringbuf sb;

  *r_string = NULL;

  /* check the outer sequence */
  if (!derlen)
    return gpg_error (GPG_ERR_INV_KEYINFO);
  c = *der++; derlen--;
  if ( c != 0x30 )
    return gpg_error (GPG_ERR_UNEXPECTED_TAG); /* not a SEQUENCE */
  TLV_LENGTH(der);
  /* and now the inner part */
  err = get_algorithm (1, der, derlen, 0x30,
                       &nread, &off, &len, &is_bitstr,
                       &parm_off, &parm_len, &parm_type);
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
    return gpg_error (GPG_ERR_UNKNOWN_ALGORITHM);
  if (!pk_algo_table[algoidx].supported)
    return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);

  if (parm_off && parm_len && parm_type == TYPE_OBJECT_ID)
    parm_oid = ksba_oid_to_str (der+parm_off, parm_len);
  else if (parm_off && parm_len)
    {
      parmder = der + parm_off;
      parmderlen = parm_len;
    }

  der += nread;
  derlen -= nread;

  if (is_bitstr)
    { /* Funny: X.509 defines the signature value as a bit string but
         CMS as an octet string - for ease of implementation we always
         allow both */
      if (!derlen)
        {
          xfree (parm_oid);
          return gpg_error (GPG_ERR_INV_KEYINFO);
        }
      c = *der++; derlen--;
      if (c)
        fprintf (stderr, "warning: number of unused bits is not zero\n");
    }

  /* fixme: we should calculate the initial length form the size of the
     sequence, so that we don't need a realloc later */
  init_stringbuf (&sb, 100);
  put_stringbuf (&sb, "(10:public-key(");

  /* fixme: we can also use the oidstring here and prefix it with
     "oid." - this way we can pass more information into Libgcrypt or
     whatever library is used */
  put_stringbuf_sexp (&sb, pk_algo_table[algoidx].algo_string);

  /* Insert the curve name for ECC. */
  if (pk_algo_table[algoidx].pkalgo == PKALGO_ECC && parm_oid)
    {
      put_stringbuf (&sb, "(");
      put_stringbuf_sexp (&sb, "curve");
      put_stringbuf_sexp (&sb, parm_oid);
      put_stringbuf (&sb, ")");
      got_curve = 1;
    }
  else if (pk_algo_table[algoidx].pkalgo == PKALGO_ED25519
           || pk_algo_table[algoidx].pkalgo == PKALGO_ED448
           || pk_algo_table[algoidx].pkalgo == PKALGO_X25519
           || pk_algo_table[algoidx].pkalgo == PKALGO_X448)
    {
      put_stringbuf (&sb, "(");
      put_stringbuf_sexp (&sb, "curve");
      put_stringbuf_sexp (&sb, pk_algo_table[algoidx].oidstring);
      put_stringbuf (&sb, ")");
    }

  /* If parameters are given and we have a description for them, parse
     them. */
  if (parmder && parmderlen
      && pk_algo_table[algoidx].parmelem_string
      && pk_algo_table[algoidx].parmctrl_string)
    {
      elem = pk_algo_table[algoidx].parmelem_string;
      ctrl = pk_algo_table[algoidx].parmctrl_string;
      for (; *elem; ctrl++, elem++)
        {
          int is_int;

          if ( (*ctrl & 0x80) && !elem[1] )
            {
              /* Hack to allow reading a raw value.  */
              is_int = 1;
              len = parmderlen;
            }
          else
            {
              if (!parmderlen)
                {
                  xfree (parm_oid);
                  return gpg_error (GPG_ERR_INV_KEYINFO);
                }
              c = *parmder++; parmderlen--;
              if ( c != *ctrl )
                {
                  xfree (parm_oid);
                  return gpg_error (GPG_ERR_UNEXPECTED_TAG);
                }
              is_int = c == 0x02;
              TLV_LENGTH (parmder);
            }
          if (is_int && *elem != '-')  /* Take this integer.  */
            {
              char tmp[2];

              put_stringbuf (&sb, "(");
              tmp[0] = *elem; tmp[1] = 0;
              put_stringbuf_sexp (&sb, tmp);
              put_stringbuf_mem_sexp (&sb, parmder, len);
              parmder += len;
              parmderlen -= len;
              put_stringbuf (&sb, ")");
            }
        }
    }
  else if (!got_curve && parmder && parmderlen
           && pk_algo_table[algoidx].pkalgo == PKALGO_ECC)
    {
      /* This is ecPublicKey but has no named curve.  This is not
       * allowed for PKIX but we try to figure the curve name out for
       * some well known curves by a simple parameter match.  */
      for (i=0; ecdomainparm_to_name[i].name; i++)
        if (ecdomainparm_to_name[i].derlen == parmderlen
            && !memcmp (ecdomainparm_to_name[i].der, parmder, parmderlen))
          {
            put_stringbuf (&sb, "(");
            put_stringbuf_sexp (&sb, "curve");
            put_stringbuf_sexp (&sb, ecdomainparm_to_name[i].name);
            put_stringbuf (&sb, ")");
            got_curve = 1;
            break;
          }
      /* if (!got_curve) */
      /*   gpgrt_log_printhex (parmder, parmderlen, "ECDomainParm:"); */
    }


  /* FIXME: We don't release the stringbuf in case of error
     better let the macro jump to a label */
  elem = pk_algo_table[algoidx].elem_string;
  ctrl = pk_algo_table[algoidx].ctrl_string;
  for (; *elem; ctrl++, elem++)
    {
      int is_int;

      if ( (*ctrl & 0x80) && !elem[1] )
        {
          /* Hack to allow reading a raw value.  */
          is_int = 1;
          len = derlen;
        }
      else
        {
          if (!derlen)
            {
              xfree (parm_oid);
              return gpg_error (GPG_ERR_INV_KEYINFO);
            }
          c = *der++; derlen--;
          if ( c != *ctrl )
            {
              xfree (parm_oid);
              return gpg_error (GPG_ERR_UNEXPECTED_TAG);
            }
          is_int = c == 0x02;
          TLV_LENGTH (der);
        }
      if (is_int && *elem != '-')  /* Take this integer.  */
        {
          char tmp[2];

          put_stringbuf (&sb, "(");
          tmp[0] = *elem; tmp[1] = 0;
          put_stringbuf_sexp (&sb, tmp);
          put_stringbuf_mem_sexp (&sb, der, len);
          der += len;
          derlen -= len;
          put_stringbuf (&sb, ")");
        }
    }
  put_stringbuf (&sb, "))");
  xfree (parm_oid);

  *r_string = get_stringbuf (&sb);
  if (!*r_string)
    return gpg_error (GPG_ERR_ENOMEM);

  return 0;
}


/* Match the algorithm string given in BUF which is of length BUFLEN
 * with the known algorithms from our table and return the table
 * entriy with the OID string.  If WITH_SIG is true, the table of
 * signature algorithms is consulted first.  */
static const char *
oid_from_buffer (const unsigned char *buf, unsigned int buflen,
                 pkalgo_t *r_pkalgo, int with_sig)
{
  int i;

  /* Ignore an optional "oid." prefix. */
  if (buflen > 4 && buf[3] == '.' && digitp (buf+4)
      && ((buf[0] == 'o' && buf[1] == 'i' && buf[2] == 'd')
          ||(buf[0] == 'O' && buf[1] == 'I' && buf[2] == 'D')))
    {
      buf += 4;
      buflen -= 4;
    }

  if (with_sig)
    {
      /* Scan the signature table first. */
      for (i=0; sig_algo_table[i].oid; i++)
        {
          if (!sig_algo_table[i].supported)
            continue;
          if (buflen == strlen (sig_algo_table[i].oidstring)
              && !memcmp (buf, sig_algo_table[i].oidstring, buflen))
            break;
          if (buflen == strlen (sig_algo_table[i].algo_string)
              && !memcmp (buf, sig_algo_table[i].algo_string, buflen))
            break;
        }
      if (sig_algo_table[i].oid)
        {
          *r_pkalgo = sig_algo_table[i].pkalgo;
          return sig_algo_table[i].oidstring;
        }
    }

  /* Scan the standard table. */
  for (i=0; pk_algo_table[i].oid; i++)
    {
      if (!pk_algo_table[i].supported)
        continue;
      if (buflen == strlen (pk_algo_table[i].oidstring)
          && !memcmp (buf, pk_algo_table[i].oidstring, buflen))
        break;
      if (buflen == strlen (pk_algo_table[i].algo_string)
          && !memcmp (buf, pk_algo_table[i].algo_string, buflen))
        break;
    }
  if (!pk_algo_table[i].oid)
    return NULL;

  *r_pkalgo = pk_algo_table[i].pkalgo;
  return pk_algo_table[i].oidstring;
}


/* If ALGOINFOMODE is false: Take the "public-key" s-expression SEXP
 * and convert it into a DER encoded publicKeyInfo.
 *
 * If ALGOINFOMODE is true: Take the "sig-val" s-expression SEXP and
 * convert it into a DER encoded algorithmInfo.  */
gpg_error_t
_ksba_keyinfo_from_sexp (ksba_const_sexp_t sexp, int algoinfomode,
                         unsigned char **r_der, size_t *r_derlen)
{
  gpg_error_t err;
  const unsigned char *s;
  char *endp;
  unsigned long n;
  const char *algo_oid;
  char *curve_oid = NULL;
  pkalgo_t pkalgo, force_pkalgo;
  int i;
  struct {
    const char *name;
    int namelen;
    const unsigned char *value;
    int valuelen;
  } parm[10];
  int parmidx;
  const char *parmdesc, *algoparmdesc;
  ksba_der_t dbld = NULL;
  ksba_der_t dbld2 = NULL;
  unsigned char *tmpder;
  size_t tmpderlen;

  if (!sexp)
    return gpg_error (GPG_ERR_INV_VALUE);

  s = sexp;
  if (*s != '(')
    return gpg_error (GPG_ERR_INV_SEXP);
  s++;

  n = strtoul (s, &endp, 10);
  s = endp;
  if (!n || *s != ':')
    return gpg_error (GPG_ERR_INV_SEXP); /* We don't allow empty lengths.  */
  s++;

  if (algoinfomode && n == 7 && !memcmp (s, "sig-val", 7))
    s += 7;
  else if (n == 10 || !memcmp (s, "public-key", 10))
    s += 10;
  else
    return gpg_error (GPG_ERR_UNKNOWN_SEXP);

  if (*s != '(')
    return gpg_error (digitp (s)? GPG_ERR_UNKNOWN_SEXP : GPG_ERR_INV_SEXP);
  s++;

  /* Break out the algorithm ID */
  n = strtoul (s, &endp, 10);
  s = endp;
  if (!n || *s != ':')
    return gpg_error (GPG_ERR_INV_SEXP); /* We don't allow empty lengths.  */
  s++;

  algo_oid = oid_from_buffer (s, n, &pkalgo, algoinfomode);
  if (!algo_oid)
    return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
  s += n;

  /* Collect all the values.  */
  force_pkalgo = 0;
  for (parmidx = 0; *s != ')' ; parmidx++)
    {
      if (parmidx >= DIM(parm))
        {
          err = gpg_error (GPG_ERR_GENERAL);
          goto leave;
        }
      if (*s != '(')
        {
          err = gpg_error (digitp(s)? GPG_ERR_UNKNOWN_SEXP:GPG_ERR_INV_SEXP);
          goto leave;
        }
      s++;
      n = strtoul (s, &endp, 10);
      s = endp;
      if (!n || *s != ':')
        {
          err = gpg_error (GPG_ERR_INV_SEXP);
          goto leave;
        }
      s++;
      parm[parmidx].name = s;
      parm[parmidx].namelen = n;
      s += n;
      if (!digitp(s))
        {
          err = gpg_error (GPG_ERR_UNKNOWN_SEXP); /* ... or invalid S-Exp. */
          goto leave;
        }

      n = strtoul (s, &endp, 10);
      s = endp;
      if (!n || *s != ':')
        return gpg_error (GPG_ERR_INV_SEXP);
      s++;
      parm[parmidx].value = s;
      parm[parmidx].valuelen = n;
      s += n;
      if ( *s != ')')
        {
          err = gpg_error (GPG_ERR_UNKNOWN_SEXP); /* ... or invalid S-Exp. */
          goto leave;
        }
      s++;

      if (parm[parmidx].namelen == 5
          && !memcmp (parm[parmidx].name, "curve", 5)
          && !curve_oid)
        {
          curve_oid = get_ecc_curve_oid (parm[parmidx].value,
                                         parm[parmidx].valuelen, &force_pkalgo);
          parmidx--; /* No need to store this parameter.  */
        }
    }
  s++;
  /* Allow for optional elements.  */
  if (*s == '(')
    {
      int depth = 1;
      err = sskip (&s, &depth);
      if (err)
        goto leave;
    }
  /* We need another closing parenthesis. */
  if ( *s != ')' )
    {
      err = gpg_error (GPG_ERR_INV_SEXP);
      goto leave;
    }

  if (force_pkalgo)
    pkalgo = force_pkalgo;

  /* Describe the parameters in the order we want them.  For DSA wie
   * also set algoparmdesc so that we can later build the parameters
   * for the algorithmIdentifier.  */
  algoparmdesc = NULL;
  switch (pkalgo)
    {
    case PKALGO_RSA:
      parmdesc = algoinfomode? "" : "ne";
      break;
    case PKALGO_DSA:
      parmdesc = algoinfomode? "" : "y";
      algoparmdesc = "pqg";
      break;
    case PKALGO_ECC:
      parmdesc = algoinfomode? "" : "q";
      break;
    case PKALGO_ED25519:
    case PKALGO_X25519:
    case PKALGO_ED448:
    case PKALGO_X448:
      parmdesc = algoinfomode? "" : "q";
      if (curve_oid)
        algo_oid = curve_oid;
      break;
    default:
      err = gpg_error (GPG_ERR_UNKNOWN_ALGORITHM);
      goto leave;
    }

  /* Create a builder. */
  dbld = _ksba_der_builder_new (0);
  if (!dbld)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* The outer sequence.  */
  if (!algoinfomode)
    _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
  /* The sequence.  */
  _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
  /* The object id.  */
  _ksba_der_add_oid (dbld, algo_oid);

  /* The parameter. */
  if (algoparmdesc)
    {
      /* Write the sequence tag followed by the integers. */
      _ksba_der_add_tag (dbld, 0, TYPE_SEQUENCE);
      for (s = algoparmdesc; *s; s++)
        for (i=0; i < parmidx; i++)
          if (parm[i].namelen == 1 && parm[i].name[0] == *s)
            {
              _ksba_der_add_int (dbld, parm[i].value, parm[i].valuelen, 1);
              break; /* inner loop */
            }
      _ksba_der_add_end (dbld);
    }
  else if (pkalgo == PKALGO_ECC && !algoinfomode)
    {
     /* We only support the namedCurve choice for ECC parameters.  */
      if (!curve_oid)
        {
          err = gpg_error (GPG_ERR_UNKNOWN_CURVE);
          goto leave;
        }
      _ksba_der_add_oid (dbld, curve_oid);
    }
  else if (pkalgo == PKALGO_RSA)
    {
      _ksba_der_add_ptr (dbld, 0, TYPE_NULL, NULL, 0);
    }

  _ksba_der_add_end (dbld); /* sequence.  */

  /* Add the bit string if we are not in algoinfomode.  */
  if (!algoinfomode)
    {
      if (*parmdesc == 'q' && !parmdesc[1])
        {
          /* This is ECC - Q is directly written as a bit string.  */
          for (i=0; i < parmidx; i++)
            if (parm[i].namelen == 1 && parm[i].name[0] == 'q')
              {
                if ((parm[i].valuelen & 1) && parm[i].valuelen > 32
                    && (parm[i].value[0] == 0x40
                        || parm[i].value[0] == 0x41
                        || parm[i].value[0] == 0x42))
                  {
                    /* Odd length and prefixed with 0x40 - this is the
                     * rfc4880bis indicator octet for extended point
                     * formats - we may not emit that octet here.  */
                    _ksba_der_add_bts (dbld, parm[i].value+1,
                                       parm[i].valuelen-1, 0);
                  }
                else
                  _ksba_der_add_bts (dbld, parm[i].value, parm[i].valuelen, 0);
                break;
              }
        }
      else  /* Non-ECC - embed the values.  */
        {
          dbld2 = _ksba_der_builder_new (10);
          if (!dbld2)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }

          /* Note that no sequence is used if only one integer is written.  */
          if (parmdesc[0] && parmdesc[1])
            _ksba_der_add_tag (dbld2, 0, TYPE_SEQUENCE);

          for (s = parmdesc; *s; s++)
            for (i=0; i < parmidx; i++)
              if (parm[i].namelen == 1 && parm[i].name[0] == *s)
                {
                  _ksba_der_add_int (dbld2, parm[i].value, parm[i].valuelen, 1);
                  break; /* inner loop */
                }

          if (parmdesc[0] && parmdesc[1])
            _ksba_der_add_end (dbld2);

          err = _ksba_der_builder_get (dbld2, &tmpder, &tmpderlen);
          if (err)
            goto leave;
          _ksba_der_add_bts (dbld, tmpder, tmpderlen, 0);
          xfree (tmpder);
        }

      _ksba_der_add_end (dbld);  /* Outer sequence.  */
    }

  /* Get the result. */
  err = _ksba_der_builder_get (dbld, r_der, r_derlen);

 leave:
  _ksba_der_release (dbld2);
  _ksba_der_release (dbld);
  xfree (curve_oid);
  return err;
}


/* Helper function to parse the parameters used for rsaPSS.
 * Given this sample DER object in (DER,DERLEN):
 *
 *  SEQUENCE {
 *    [0] {
 *      SEQUENCE {
 *        OBJECT IDENTIFIER sha-512 (2 16 840 1 101 3 4 2 3)
 *        }
 *      }
 *    [1] {
 *      SEQUENCE {
 *        OBJECT IDENTIFIER pkcs1-MGF (1 2 840 113549 1 1 8)
 *        SEQUENCE {
 *          OBJECT IDENTIFIER sha-512 (2 16 840 1 101 3 4 2 3)
 *          }
 *        }
 *      }
 *    [2] {
 *      INTEGER 64
 *       }
 *     }
 *
 * The function returns the first OID at R_PSSHASH and the salt length
 * at R_SALTLEN.  If the salt length is missing its default value is
 * returned.  In case object does not resemble a the expected rsaPSS
 * parameters GPG_ERR_INV_OBJ is returned; other errors are returned
 * for an syntatically invalid object.  On error NULL is stored at
 * R_PSSHASH.
 */
gpg_error_t
_ksba_keyinfo_get_pss_info (const unsigned char *der, size_t derlen,
                            char **r_psshash, unsigned int *r_saltlen)
{
  gpg_error_t err;
  struct tag_info ti;
  char *psshash = NULL;
  char *tmpoid = NULL;
  unsigned int saltlen;

  *r_psshash = NULL;
  *r_saltlen = 0;

  err = parse_sequence (&der, &derlen, &ti);
  if (err)
    goto leave;

  /* Get the hash algo.  */
  err = parse_context_tag (&der, &derlen, &ti, 0);
  if (err)
    goto unknown_parms;
  err = parse_sequence (&der, &derlen, &ti);
  if (err)
    goto unknown_parms;
  err = parse_object_id_into_str (&der, &derlen, &psshash);
  if (err)
    goto unknown_parms;
  err = parse_optional_null (&der, &derlen, NULL);
  if (err)
    goto unknown_parms;

  /* Check the MGF OID and that its hash algo matches. */
  err = parse_context_tag (&der, &derlen, &ti, 1);
  if (err)
    goto unknown_parms;
  err = parse_sequence (&der, &derlen, &ti);
  if (err)
    goto leave;
  err = parse_object_id_into_str (&der, &derlen, &tmpoid);
  if (err)
    goto unknown_parms;
  if (strcmp (tmpoid, "1.2.840.113549.1.1.8"))  /* MGF1 */
    goto unknown_parms;
  err = parse_sequence (&der, &derlen, &ti);
  if (err)
    goto leave;
  xfree (tmpoid);
  err = parse_object_id_into_str (&der, &derlen, &tmpoid);
  if (err)
    goto unknown_parms;
  if (strcmp (tmpoid, psshash))
    goto unknown_parms;
  err = parse_optional_null (&der, &derlen, NULL);
  if (err)
    goto unknown_parms;

  /* Get the optional saltLength.  */
  err = parse_context_tag (&der, &derlen, &ti, 2);
  if (gpg_err_code (err) == GPG_ERR_INV_OBJ
      || gpg_err_code (err) == GPG_ERR_FALSE)
    saltlen = 20; /* Optional element - use default value */
  else if (err)
    goto unknown_parms;
  else
    {
      err = parse_integer (&der, &derlen, &ti);
      if (err)
        goto leave;
      for (saltlen=0; ti.length; ti.length--)
        {
          saltlen <<= 8;
          saltlen |= (*der++) & 0xff;
          derlen--;
        }
    }

  /* All fine.  */
  *r_psshash = psshash;
  psshash = NULL;
  *r_saltlen = saltlen;
  err = 0;
  goto leave;

 unknown_parms:
  err = gpg_error (GPG_ERR_INV_OBJ);

 leave:
  xfree (psshash);
  xfree (tmpoid);
  return err;
}


/* Mode 0: work as described under _ksba_sigval_to_sexp
 * mode 1: work as described under _ksba_encval_to_sexp
 * mode 2: same as mode 1 but for ECDH; in this mode
 *         KEYENCRYALO, KEYWRAPALGO, ENCRKEY, ENCRYKLEYLEN
 *         are also required.
 */
static gpg_error_t
cryptval_to_sexp (int mode, const unsigned char *der, size_t derlen,
                  const char *keyencralgo, const char *keywrapalgo,
                  const void *encrkey, size_t encrkeylen,
                  ksba_sexp_t *r_string)
{
  gpg_error_t err;
  const struct algo_table_s *algo_table;
  int c;
  size_t nread, off, len;
  int algoidx;
  int is_bitstr;
  const unsigned char *ctrl;
  const char *elem;
  struct stringbuf sb;
  size_t parm_off, parm_len;
  int parm_type;
  char *pss_hash = NULL;
  unsigned int salt_length = 0;

  /* FIXME: The entire function is very similar to keyinfo_to_sexp */
  *r_string = NULL;

  if (!mode)
    algo_table = sig_algo_table;
  else
    algo_table = enc_algo_table;

  err = get_algorithm (1, der, derlen, 0x30,
                       &nread, &off, &len, &is_bitstr,
                       &parm_off, &parm_len, &parm_type);
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
    return gpg_error (GPG_ERR_UNKNOWN_ALGORITHM);
  if (!algo_table[algoidx].supported)
    return gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);

  if (parm_type == TYPE_SEQUENCE
      && algo_table[algoidx].supported == SUPPORTED_RSAPSS)
    {
      /* This is rsaPSS and we collect the parameters.  We simplify
       * this by assuming that pkcs1-MGF is used with an identical
       * hash algorithm.  All other kinds of parameters are ignored.  */
      err = _ksba_keyinfo_get_pss_info (der + parm_off, parm_len,
                                        &pss_hash, &salt_length);
      if (gpg_err_code (err) == GPG_ERR_INV_OBJ)
        err = 0;
      if (err)
        return err;
    }


  der += nread;
  derlen -= nread;

  if (is_bitstr)
    { /* Funny: X.509 defines the signature value as a bit string but
         CMS as an octet string - for ease of implementation we always
         allow both */
      if (!derlen)
        return gpg_error (GPG_ERR_INV_KEYINFO);
      c = *der++; derlen--;
      if (c)
        fprintf (stderr, "warning: number of unused bits is not zero\n");
    }

  /* fixme: we should calculate the initial length form the size of the
     sequence, so that we don't neen a realloc later */
  init_stringbuf (&sb, 100);
  put_stringbuf (&sb, mode? "(7:enc-val(":"(7:sig-val(");
  put_stringbuf_sexp (&sb, algo_table[algoidx].algo_string);

  /* FIXME: We don't release the stringbuf in case of error
     better let the macro jump to a label */
  if (!mode && (algo_table[algoidx].pkalgo == PKALGO_ED25519
                ||algo_table[algoidx].pkalgo == PKALGO_ED448
                || (algo_table[algoidx].pkalgo == PKALGO_ECC
                    && *algo_table[algoidx].elem_string == 'P')))
    {
      /* EdDSA is special: R and S are simply concatenated; see
       * rfc8410.  The same code is used for Plain ECDSA format as
       * specified in BSI TR-03111; we indicate this with a 'P' in the
       * elem string.  */
      put_stringbuf (&sb, "(1:r");
      put_stringbuf_mem_sexp (&sb, der, derlen/2);
      put_stringbuf (&sb, ")");
      der += derlen/2;
      derlen /= 2;
      put_stringbuf (&sb, "(1:s");
      put_stringbuf_mem_sexp (&sb, der, derlen);
      put_stringbuf (&sb, ")");
    }
  else
    {
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
                return gpg_error (GPG_ERR_INV_KEYINFO);
              c = *der++; derlen--;
              if ( c != *ctrl )
                return gpg_error (GPG_ERR_UNEXPECTED_TAG);
              is_int = c == 0x02;
              TLV_LENGTH (der);
            }
          if (is_int && *elem != '-')
            { /* take this integer */
              char tmp[2];

              put_stringbuf (&sb, "(");
              tmp[0] = *elem; tmp[1] = 0;
              put_stringbuf_sexp (&sb, tmp);
              put_stringbuf_mem_sexp (&sb, der, len);
              der += len;
              derlen -= len;
              put_stringbuf (&sb, ")");
            }
        }
    }
  if (mode == 2)  /* ECDH */
    {
      put_stringbuf (&sb, "(1:s");
      put_stringbuf_mem_sexp (&sb, encrkey, encrkeylen);
      put_stringbuf (&sb, ")");
    }
  put_stringbuf (&sb, ")");
  if (!mode && algo_table[algoidx].digest_string)
    {
      /* Insert the hash algorithm if included in the OID.  */
      put_stringbuf (&sb, "(4:hash");
      put_stringbuf_sexp (&sb, algo_table[algoidx].digest_string);
      put_stringbuf (&sb, ")");
    }
  if (!mode && pss_hash)
    {
      put_stringbuf (&sb, "(5:flags3:pss)");
      put_stringbuf (&sb, "(9:hash-algo");
      put_stringbuf_sexp (&sb, pss_hash);
      put_stringbuf (&sb, ")");
      put_stringbuf (&sb, "(11:salt-length");
      put_stringbuf_uint (&sb, salt_length);
      put_stringbuf (&sb, ")");
    }
  if (mode == 2)  /* ECDH */
    {
      put_stringbuf (&sb, "(9:encr-algo");
      put_stringbuf_sexp (&sb, keyencralgo);
      put_stringbuf (&sb, ")(9:wrap-algo");
      put_stringbuf_sexp (&sb, keywrapalgo);
      put_stringbuf (&sb, ")");
    }
  put_stringbuf (&sb, ")");

  *r_string = get_stringbuf (&sb);
  if (!*r_string)
    return gpg_error (GPG_ERR_ENOMEM);

  xfree (pss_hash);
  return 0;
}

/* Assume that DER is a buffer of length DERLEN with a DER encoded
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
      (<param_namen> <mpi>))
    (hash algo))

 The S-Exp will be returned in a string which the caller must free.
 We don't pass an ASN.1 node here but a plain memory block.  */
gpg_error_t
_ksba_sigval_to_sexp (const unsigned char *der, size_t derlen,
                      ksba_sexp_t *r_string)
{
  return cryptval_to_sexp (0, der, derlen, NULL, NULL, NULL, 0, r_string);
}


/* Assume that der is a buffer of length DERLEN with a DER encoded
 * ASN.1 structure like this:
 *
 *    SEQUENCE {
 *       algorithm    OBJECT IDENTIFIER,
 *       parameters   ANY DEFINED BY algorithm OPTIONAL
 *    }
 *    encryptedKey  OCTET STRING
 *
 * The function parses this structure and creates a S-expression
 * suitable to be used as encrypted value in Libgcrypt's public key
 * functions:
 *
 * (enc-val
 *   (<algo>
 *     (<param_name1> <mpi>)
 *     ...
 *     (<param_namen> <mpi>)
 *   ))
 *
 * The S-expression will be returned in a string which the caller must
 * free.  Note that the input buffer may not a proper ASN.1 object but
 * a plain memory block; this is becuase the SEQUENCE is followed by
 * an OCTET STRING or BIT STRING.
 */
gpg_error_t
_ksba_encval_to_sexp (const unsigned char *der, size_t derlen,
                      ksba_sexp_t *r_string)
{
  return cryptval_to_sexp (1, der, derlen, NULL, NULL, NULL, 0, r_string);
}


/* Assume that der is a buffer of length DERLEN with a DER encoded
 * ASN.1 structure like this:
 *
 *  [1] {
 *    SEQUENCE {
 *       algorithm    OBJECT IDENTIFIER,
 *       parameters   ANY DEFINED BY algorithm OPTIONAL
 *    }
 *    encryptedKey  BIT STRING
 *  }
 *
 * The function parses this structure and creates an S-expression
 * conveying all parameters required for ECDH:
 *
 * (enc-val
 *   (ecdh
 *     (e <octetstring>)
 *     (s <octetstring>)
 *   (ukm <octetstring>)
 *   (encr-algo <oid>)
 *   (wrap-algo <oid>)))
 *
 * E is the ephemeral public key and S is the encrypted key.  The user
 * keying material (ukm) is optional.  The S-expression will be
 * returned in a string which the caller must free.
 */
gpg_error_t
_ksba_encval_kari_to_sexp (const unsigned char *der, size_t derlen,
                           const char *keyencralgo, const char *keywrapalgo,
                           const void *enckey, size_t enckeylen,
                           ksba_sexp_t *r_string)
{
  gpg_error_t err;
  struct tag_info ti;
  size_t save_derlen = derlen;

  err = parse_context_tag (&der, &derlen, &ti, 1);
  if (err)
    return err;
  if (save_derlen < ti.nhdr)
    return gpg_error (GPG_ERR_INV_BER);
  derlen = save_derlen - ti.nhdr;
  return cryptval_to_sexp (2, der, derlen,
                           keyencralgo, keywrapalgo, enckey, enckeylen,
                           r_string);
}
