/* ksba.h - X509 library for the Aegypten project
 *      Copyright (C) 2001, 2002 g10 Code GmbH
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

#ifndef KSBA_H
#define KSBA_H 1

#include <time.h>

#ifdef __cplusplus
extern "C" { 
#if 0
 }
#endif
#endif


/* Check for compiler features.  */
#ifdef __GNUC__
#define _KSBA_GCC_VERSION (__GNUC__ * 10000 \
                            + __GNUC_MINOR__ * 100 \
                            + __GNUC_PATCHLEVEL__)
/* #if _KSBA_GCC_VERSION > 30100 */
/* #define _KSBA_DEPRECATED	__attribute__ ((__deprecated__)) */
/* #endif */
#endif /*__GNUC__*/

#ifndef _KSBA_DEPRECATED
#define _KSBA_DEPRECATED
#endif



typedef enum {
  KSBA_EOF = -1,
  KSBA_No_Error = 0,
  KSBA_General_Error = 1,
  KSBA_Out_Of_Core = 2,
  KSBA_Invalid_Value = 3,
  KSBA_Not_Implemented = 4,
  KSBA_Conflict = 5,
  KSBA_Read_Error = 6,
  KSBA_Write_Error = 7,
  KSBA_Invalid_Attr = 8,
  KSBA_No_Data = 9,
  KSBA_No_Value = 10,
  KSBA_Bug = 11,
  KSBA_BER_Error = 12,
  KSBA_Element_Not_Found = 13,
  KSBA_Identifier_Not_Found = 14,
  KSBA_Value_Not_Found = 15,  /* Note, that this is not the same as No Value */
  KSBA_Syntax_Error = 16,
  KSBA_Invalid_Tag = 17,
  KSBA_Invalid_Length = 18,
  KSBA_Invalid_Keyinfo = 19,
  KSBA_Unexpected_Tag = 20,
  KSBA_Not_DER_Encoded = 21,
  KSBA_Unknown_Algorithm = 22,
  KSBA_Unsupported_Algorithm = 23,
  KSBA_Object_Too_Large = 24,
  KSBA_Object_Too_Short = 25,
  KSBA_No_CMS_Object = 26,
  KSBA_Unknown_CMS_Object = 27,
  KSBA_Unsupported_CMS_Object = 28,
  KSBA_Invalid_CMS_Object = 29,
  KSBA_Unsupported_CMS_Version = 30,
  KSBA_Unsupported_Encoding = 31,
  KSBA_Missing_Value = 32,
  KSBA_Invalid_State = 33,
  KSBA_Duplicate_Value = 34,
  KSBA_Missing_Action = 35,
  KSBA_File_Error = 36,
  KSBA_Module_Not_Found = 37,
  KSBA_Encoding_Error = 38,
  KSBA_Invalid_Index = 39,
  KSBA_Invalid_OID_String = 40,
  KSBA_Invalid_Sexp = 41,
  KSBA_Unknown_Sexp = 42,
  KSBA_Invalid_Time = 43,
  KSBA_User_Error = 44,        /* may be used by callbacks */
  KSBA_Buffer_Too_Short = 45,
  KSBA_Invalid_CRL_Object = 46,
  KSBA_Unsupported_CRL_Version = 47,
  KSBA_Unknown_Name = 48,
  KSBA_Invalid_Cert_Object =49
} KsbaError;


typedef enum {
  KSBA_CT_NONE = 0,
  KSBA_CT_DATA = 1,
  KSBA_CT_SIGNED_DATA = 2,
  KSBA_CT_ENVELOPED_DATA = 3,
  KSBA_CT_DIGESTED_DATA = 4,
  KSBA_CT_ENCRYPTED_DATA = 5,
  KSBA_CT_AUTH_DATA = 6
} ksba_content_type_t;
typedef ksba_content_type_t KsbaContentType _KSBA_DEPRECATED;



typedef enum {
  KSBA_SR_NONE = 0,     /* never seen by libgcrypt user */
  KSBA_SR_RUNNING = 1,  /* never seen by libgcrypt user */
  KSBA_SR_GOT_CONTENT = 2,
  KSBA_SR_NEED_HASH = 3,
  KSBA_SR_BEGIN_DATA = 4,
  KSBA_SR_END_DATA = 5,
  KSBA_SR_READY = 6,
  KSBA_SR_NEED_SIG = 7,
  KSBA_SR_DETACHED_DATA = 8,
  KSBA_SR_BEGIN_ITEMS = 9,
  KSBA_SR_GOT_ITEM = 10,
  KSBA_SR_END_ITEMS = 11,
} ksba_stop_reason_t;
typedef ksba_stop_reason_t KsbaStopReason _KSBA_DEPRECATED;

typedef enum {
  KSBA_CRLREASON_UNSPECIFIED = 1,
  KSBA_CRLREASON_KEY_COMPROMISE = 2,
  KSBA_CRLREASON_CA_COMPROMISE = 4,
  KSBA_CRLREASON_AFFILIATION_CHANGED = 8,
  KSBA_CRLREASON_SUPERSEDED = 16,
  KSBA_CRLREASON_CESSATION_OF_OPERATION = 32,
  KSBA_CRLREASON_CERTIFICATE_HOLD = 64,
  KSBA_CRLREASON_REMOVE_FROM_CRL = 256
} ksba_crl_reason_t;
typedef ksba_crl_reason_t KsbaCRLReason _KSBA_DEPRECATED;

typedef enum {
  KSBA_KEYUSAGE_DIGITAL_SIGNATURE =  1,
  KSBA_KEYUSAGE_NON_REPUDIATION   =  2,
  KSBA_KEYUSAGE_KEY_ENCIPHERMENT  =  4,
  KSBA_KEYUSAGE_DATA_ENCIPHERMENT =  8,
  KSBA_KEYUSAGE_KEY_AGREEMENT     = 16,
  KSBA_KEYUSAGE_KEY_CERT_SIGN     = 32,     
  KSBA_KEYUSAGE_CRL_SIGN          = 64,
  KSBA_KEYUSAGE_ENCIPHER_ONLY    = 128,
  KSBA_KEYUSAGE_DECIPHER_ONLY    = 256
} ksba_key_usage_t;
typedef ksba_key_usage_t KsbaKeyUsage _KSBA_DEPRECATED;


/* ISO format, e.g. "19610711T172059", assumed to be UTC. */
typedef char ksba_isotime_t[16];


/* X.509 certificates are represented by this object.
   ksba_cert_new() creates such an object */
struct ksba_cert_s;
typedef struct ksba_cert_s *ksba_cert_t;
typedef struct ksba_cert_s *KsbaCert _KSBA_DEPRECATED;

/* CMS objects are controlled by this object.
   ksba_cms_new() creates it */
struct ksba_cms_s;
typedef struct ksba_cms_s *ksba_cms_t;
typedef struct ksba_cms_s *KsbaCMS _KSBA_DEPRECATED;

/* CRL objects are controlled by this object.
   ksba_crl_new() creates it */
struct ksba_crl_s;
typedef struct ksba_crl_s *ksba_crl_t;
typedef struct ksba_crl_s *KsbaCRL _KSBA_DEPRECATED;

/* PKCS-10 creation is controlled by this object.
   ksba_certreq_new() creates it */
struct ksba_certreq_s;
typedef struct ksba_certreq_s *ksba_certreq_t;
typedef struct ksba_certreq_s *KsbaCertreq _KSBA_DEPRECATED;

/* This is a reader object vor various purposes
   see ksba_reader_new et al. */
struct ksba_reader_s;
typedef struct ksba_reader_s *ksba_reader_t;
typedef struct ksba_reader_s *KsbaReader _KSBA_DEPRECATED;

/* This is a writer object vor various purposes
   see ksba_writer_new et al. */
struct ksba_writer_s;
typedef struct ksba_writer_s *ksba_writer_t;
typedef struct ksba_writer_s *KsbaWriter _KSBA_DEPRECATED;

/* This is an object to store an ASN.1 parse tree as
   create by ksba_asn_parse_file() */
struct ksba_asn_tree_s;
typedef struct ksba_asn_tree_s *ksba_asn_tree_t;
typedef struct ksba_asn_tree_s *KsbaAsnTree _KSBA_DEPRECATED;

/* This is an object to reference an General Name.  Such an object is
   returned by several functions. */
struct ksba_name_s;
typedef struct ksba_name_s *ksba_name_t;
typedef struct ksba_name_s *KsbaName _KSBA_DEPRECATED;

/* KsbaSexp is just an unsigned char * which should be used for
   documentation purpose.  The S-expressions returned by libksba are
   always in canonical representation with an extra 0 byte at the end,
   so that one can print the values in the debugger and at least see
   the first bytes */
typedef unsigned char *ksba_sexp_t;
typedef unsigned char *KsbaSexp _KSBA_DEPRECATED;
typedef const unsigned char *ksba_const_sexp_t;
typedef const unsigned char *KsbaConstSexp _KSBA_DEPRECATED;
   

/*-- cert.c --*/
ksba_cert_t ksba_cert_new (void);
void        ksba_cert_ref (ksba_cert_t cert);
void        ksba_cert_release (ksba_cert_t cert);
KsbaError   ksba_cert_read_der (ksba_cert_t cert, ksba_reader_t reader);
KsbaError   ksba_cert_init_from_mem (ksba_cert_t cert,
                                     const void *buffer, size_t length);
const unsigned char *ksba_cert_get_image (ksba_cert_t cert, size_t *r_length);
KsbaError ksba_cert_hash (ksba_cert_t cert, int what,
                          void (*hasher)(void *,
                                         const void *,
                                         size_t length), 
                          void *hasher_arg);
const char *ksba_cert_get_digest_algo (ksba_cert_t cert);
ksba_sexp_t ksba_cert_get_serial (ksba_cert_t cert);
char       *ksba_cert_get_issuer (ksba_cert_t cert, int idx);
KsbaError   ksba_cert_get_validity (ksba_cert_t cert, int what,
                                    ksba_isotime_t r_time);
char       *ksba_cert_get_subject (ksba_cert_t cert, int idx);
KsbaSexp    ksba_cert_get_public_key (ksba_cert_t cert);
KsbaSexp    ksba_cert_get_sig_val (ksba_cert_t cert);

KsbaError ksba_cert_get_extension (ksba_cert_t cert, int idx,
                                   char const **r_oid, int *r_crit,
                                   size_t *r_deroff, size_t *r_derlen);

KsbaError ksba_cert_is_ca (ksba_cert_t cert, int *r_ca, int *r_pathlen);
KsbaError ksba_cert_get_key_usage (ksba_cert_t cert, unsigned int *r_flags);
KsbaError ksba_cert_get_cert_policies (ksba_cert_t cert, char **r_policies);
KsbaError ksba_cert_get_crl_dist_point (ksba_cert_t cert, int idx,
                                        ksba_name_t *r_distpoint,
                                        ksba_name_t *r_issuer,
                                        ksba_crl_reason_t *r_reason);
KsbaError ksba_cert_get_auth_key_id (ksba_cert_t cert,
                                     ksba_sexp_t *r_keyid,
                                     ksba_name_t *r_name,
                                     ksba_sexp_t *r_serial);


/*-- cms.c --*/
KsbaContentType ksba_cms_identify (ksba_reader_t reader);

KsbaCMS ksba_cms_new (void);
void    ksba_cms_release (ksba_cms_t cms);
KsbaError ksba_cms_set_reader_writer (ksba_cms_t cms, KsbaReader r, KsbaWriter w);

KsbaError ksba_cms_parse (ksba_cms_t cms, KsbaStopReason *r_stopreason);
KsbaError ksba_cms_build (ksba_cms_t cms, KsbaStopReason *r_stopreason);

KsbaContentType ksba_cms_get_content_type (ksba_cms_t cms, int what);
const char *ksba_cms_get_content_oid (ksba_cms_t cms, int what);
KsbaError ksba_cms_get_content_enc_iv (ksba_cms_t cms, unsigned char *iv,
                                       size_t maxivlen, size_t *ivlen);
const char *ksba_cms_get_digest_algo_list (ksba_cms_t cms, int idx);
KsbaError ksba_cms_get_issuer_serial (ksba_cms_t cms, int idx,
                                      char **r_issuer,
                                      ksba_sexp_t *r_serial);
const char *ksba_cms_get_digest_algo (ksba_cms_t cms, int idx);
ksba_cert_t ksba_cms_get_cert (ksba_cms_t cms, int idx);
KsbaError ksba_cms_get_message_digest (ksba_cms_t cms, int idx,
                                       char **r_digest, size_t *r_digest_len);
KsbaError ksba_cms_get_signing_time (ksba_cms_t cms, int idx,
                                     ksba_isotime_t r_sigtime);
KsbaError ksba_cms_get_sigattr_oids (ksba_cms_t cms, int idx,
                                     const char *reqoid, char **r_value);
KsbaSexp ksba_cms_get_sig_val (ksba_cms_t cms, int idx);
KsbaSexp ksba_cms_get_enc_val (ksba_cms_t cms, int idx);

void
ksba_cms_set_hash_function (ksba_cms_t cms,
                            void (*hash_fnc)(void *, const void *, size_t),
                            void *hash_fnc_arg);

KsbaError ksba_cms_hash_signed_attrs (ksba_cms_t cms, int idx);


KsbaError ksba_cms_set_content_type (ksba_cms_t cms, int what,
                                     ksba_content_type_t type);
KsbaError ksba_cms_add_digest_algo (ksba_cms_t cms, const char *oid);
KsbaError ksba_cms_add_signer (ksba_cms_t cms, ksba_cert_t cert);
KsbaError ksba_cms_add_cert (ksba_cms_t cms, ksba_cert_t cert);
KsbaError ksba_cms_set_message_digest (ksba_cms_t cms, int idx,
                                       const char *digest,
                                       size_t digest_len);
KsbaError ksba_cms_set_signing_time (ksba_cms_t cms, int idx,
                                     const ksba_isotime_t sigtime);
KsbaError ksba_cms_set_sig_val (ksba_cms_t cms,
                                int idx, ksba_const_sexp_t sigval);

KsbaError ksba_cms_set_content_enc_algo (ksba_cms_t cms,
                                         const char *oid,
                                         const unsigned char *iv,
                                         size_t ivlen);
KsbaError ksba_cms_add_recipient (ksba_cms_t cms, ksba_cert_t cert);
KsbaError ksba_cms_set_enc_val (ksba_cms_t cms,
                                int idx, ksba_const_sexp_t encval);


/*-- crl.c --*/
ksba_crl_t   ksba_crl_new (void);
void      ksba_crl_release (ksba_crl_t crl);
KsbaError ksba_crl_set_reader (ksba_crl_t crl, KsbaReader r);
void      ksba_crl_set_hash_function (ksba_crl_t crl,
                            void (*hash_fnc)(void *, const void *, size_t),
                            void *hash_fnc_arg);
const char *ksba_crl_get_digest_algo (ksba_crl_t crl);
KsbaError ksba_crl_get_issuer (ksba_crl_t crl, char **r_issuer);
KsbaError ksba_crl_get_update_times (ksba_crl_t crl,
                                     ksba_isotime_t this,
                                     ksba_isotime_t next);
KsbaError ksba_crl_get_item (ksba_crl_t crl,
                             ksba_sexp_t *r_serial,
                             ksba_isotime_t r_revocation_date,
                             ksba_crl_reason_t *r_reason);
KsbaSexp  ksba_crl_get_sig_val (ksba_crl_t crl);
KsbaError ksba_crl_parse (ksba_crl_t crl, ksba_stop_reason_t *r_stopreason);

/*-- certreq.c --*/
ksba_certreq_t ksba_certreq_new (void);
void      ksba_certreq_release (ksba_certreq_t cr);
KsbaError ksba_certreq_set_writer (ksba_certreq_t cr, KsbaWriter w);
void      ksba_certreq_set_hash_function (
                               ksba_certreq_t cr,
                               void (*hash_fnc)(void *, const void *, size_t),
                               void *hash_fnc_arg);
KsbaError ksba_certreq_add_subject (ksba_certreq_t cr, const char *name);
KsbaError ksba_certreq_set_public_key (ksba_certreq_t cr,
                                       ksba_const_sexp_t key);
KsbaError ksba_certreq_set_sig_val (ksba_certreq_t cr,
                                    ksba_const_sexp_t sigval);
KsbaError ksba_certreq_build (ksba_certreq_t cr,
                              ksba_stop_reason_t *r_stopreason);


/*-- reader.c --*/
ksba_reader_t ksba_reader_new (void);
void       ksba_reader_release (ksba_reader_t r);
int        ksba_reader_error (ksba_reader_t r);

KsbaError ksba_reader_set_mem (ksba_reader_t r,
                               const void *buffer, size_t length);
KsbaError ksba_reader_set_fd (ksba_reader_t r, int fd);
KsbaError ksba_reader_set_file (ksba_reader_t r, FILE *fp);
KsbaError ksba_reader_set_cb (ksba_reader_t r, 
                              int (*cb)(void*,char *,size_t,size_t*),
                              void *cb_value );

KsbaError ksba_reader_read (ksba_reader_t r,
                            char *buffer, size_t length, size_t *nread);
KsbaError ksba_reader_unread (ksba_reader_t r, const void *buffer, size_t count);
unsigned long ksba_reader_tell (ksba_reader_t r);

/*-- writer.c --*/
ksba_writer_t ksba_writer_new (void);
void       ksba_writer_release (ksba_writer_t r);
int ksba_writer_error (ksba_writer_t w);
unsigned long ksba_writer_tell (ksba_writer_t w);
KsbaError ksba_writer_set_fd (ksba_writer_t w, int fd);
KsbaError ksba_writer_set_file (ksba_writer_t w, FILE *fp);
KsbaError ksba_writer_set_cb (ksba_writer_t w, 
                              int (*cb)(void*,const void *,size_t),
                              void *cb_value);
KsbaError ksba_writer_set_mem (ksba_writer_t w, size_t initial_size);
const void *ksba_writer_get_mem (ksba_writer_t w, size_t *nbytes);
void *      ksba_writer_snatch_mem (ksba_writer_t w, size_t *nbytes);
KsbaError 
ksba_writer_set_filter (ksba_writer_t w, 
                        KsbaError (*filter)(void*,
                                            const void *,size_t, size_t *,
                                            void *, size_t, size_t *),
                        void *filter_arg);

KsbaError ksba_writer_write (ksba_writer_t w, const void *buffer, size_t length);
KsbaError ksba_writer_write_octet_string (ksba_writer_t w,
                                          const void *buffer, size_t length,
                                          int flush);

/*-- asn1-parse.y --*/
int ksba_asn_parse_file (const char *filename, ksba_asn_tree_t *result,
                         int debug);
void ksba_asn_tree_release (ksba_asn_tree_t tree);

/*-- asn1-func.c --*/
void ksba_asn_tree_dump (ksba_asn_tree_t tree, const char *name, FILE *fp);
KsbaError ksba_asn_create_tree (const char *mod_name, ksba_asn_tree_t *result);

/*-- oid.c --*/
char *ksba_oid_to_str (const char *buffer, size_t length);
int ksba_oid_from_str (const char *string, char **rbuf, size_t *rlength);


/*-- name.c --*/
ksba_name_t ksba_name_new (void);
void ksba_name_ref (ksba_name_t name);
void ksba_name_release (ksba_name_t name);
const char *ksba_name_enum (ksba_name_t name, int idx);
char *ksba_name_get_uri (ksba_name_t name, int idx);


/*-- util.c --*/
void ksba_set_malloc_hooks ( void *(*new_alloc_func)(size_t n),
                             void *(*new_realloc_func)(void *p, size_t n),
                             void (*new_free_func)(void*) );
void *ksba_malloc (size_t n );
void *ksba_calloc (size_t n, size_t m );
void *ksba_realloc (void *p, size_t n);
char *ksba_strdup (const char *p);
void  ksba_free ( void *a );

/*--version.c --*/
const char *ksba_check_version (const char *req_version);

/*-- errors.c (generated from this file) --*/
const char *ksba_strerror (KsbaError err);

#ifdef __cplusplus
}
#endif
#endif /*KSBA_H*/



