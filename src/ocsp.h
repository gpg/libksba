/* ocsp.h - OCSP (rfc2560)
 *      Copyright (C) 2003 g10 Code GmbH
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

#ifndef OCSP_H
#define OCSP_H 1

#include "ksba.h"

typedef enum
  {
    KSBA_OCSP_RSPSTATUS_SUCCESS = 0,
    KSBA_OCSP_RSPSTATUS_MALFORMED = 1,
    KSBA_OCSP_RSPSTATUS_INTERNAL = 2,
    KSBA_OCSP_RSPSTATUS_TRYLATER = 3,
    KSBA_OCSP_RSPSTATUS_SIGREQUIRED = 5,
    KSBA_OCSP_RSPSTATUS_UNAUTHORIZED = 6,
    KSBA_OCSP_RSPSTATUS_OTHER = 254,
    KSBA_OCSP_RSPSTATUS_NONE = 255
  } 
ksba_ocsp_response_status_t;


/* A structure to keep a information about a single status request. */
struct ocsp_reqitem_s {
  struct ocsp_reqitem_s *next;

  ksba_cert_t cert;        /* The target certificate for the request. */
  ksba_cert_t issuer_cert; /* And the certificate of the issuer. */

  /* The next 4 fields are used to match a response with a request. */
  unsigned char issuer_name_hash[20]; /* The hash as used by the request. */
  unsigned char issuer_key_hash[20];  /* The hash as used by the request. */
  unsigned char *serialno; /* A malloced copy of the serial number. */
  size_t serialnolen;      /* and its length. */

  /* The actual status as parsed from the response. */
  int got_answer;          /* Set to true if a corresponding response
                              has been found. */
  int is_revoked;          /* Set to true if the target certificate
                              has been revoked. */
  ksba_isotime_t this_update;  /* The thisUpdate value from the response. */
  ksba_isotime_t next_update;  /* The nextUpdate value from the response. */
  ksba_isotime_t revocation_time; /* The indicated revocation time. */

};


/* A structure to store certificates read from a response. */
struct ocsp_certlist_s {
  struct ocsp_certlist_s *next;
  ksba_cert_t cert;
};



/* A structure used as context for the ocsp subsystem. */
struct ksba_ocsp_s {

  char *digest_oid;        /* The OID of the digest algorithm to be
                              used for a request. */

  ksba_reader_t reader;    /* The reader used to parse responses. */

  /* The hash fucntion and its argument to be used by this object. */
  void (*hash_fnc)(void *, const void *, size_t);
  void *hash_fnc_arg;

  struct ocsp_reqitem_s *requestlist;  /* The list of request items. */

  size_t hash_offset;      /* What area of a response is to be */
  size_t hash_length;      /* hashed. */

  ksba_ocsp_response_status_t response_status; /* Status of the response. */
  ksba_sexp_t sigval;     /* The signature value. */
  struct ocsp_certlist_s *received_certs; /* Certificates received in
                                             the response. */

};




/* Stuff to be moved into ksba.h */


typedef struct ksba_ocsp_s *ksba_ocsp_t;

gpg_error_t ksba_ocsp_new (ksba_ocsp_t *r_oscp);
void ksba_ocsp_release (ksba_ocsp_t ocsp);
gpg_error_t ksba_ocsp_add_certs (ksba_ocsp_t ocsp,
                                 ksba_cert_t cert, ksba_cert_t issuer_cert);
gpg_error_t ksba_ocsp_set_digest_algo (ksba_ocsp_t ocsp, const char *oid);
gpg_error_t ksba_ocsp_build_request (ksba_ocsp_t ocsp,
                                     unsigned char **r_buffer,
                                     size_t *r_buflen);


gpg_error_t ksba_ocsp_parse_response (
                                 ksba_ocsp_t ocsp,
                                 const unsigned char *msg, size_t msglen,
                                 ksba_ocsp_response_status_t *response_status);

const char *ksba_ocsp_get_digest_algo (ksba_ocsp_t ocsp);

gpg_error_t ksba_ocsp_hash_response (ksba_ocsp_t ocsp,
                                     const unsigned char *msg, size_t msglen,
                                     void (*hasher)(void *, const void *,
                                                    size_t length), 
                                     void *hasher_arg);

ksba_sexp_t ksba_ocsp_get_sig_val (ksba_ocsp_t ocsp);


#endif /*OCSP_H*/
