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
} KsbaContentType;


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
} KsbaStopReason;

typedef enum {
  KSBA_CRLREASON_UNSPECIFIED = 1,
  KSBA_CRLREASON_KEY_COMPROMISE = 2,
  KSBA_CRLREASON_CA_COMPROMISE = 4,
  KSBA_CRLREASON_AFFILIATION_CHANGED = 8,
  KSBA_CRLREASON_SUPERSEDED = 16,
  KSBA_CRLREASON_CESSATION_OF_OPERATION = 32,
  KSBA_CRLREASON_CERTIFICATE_HOLD = 64,
  KSBA_CRLREASON_REMOVE_FROM_CRL = 256
} KsbaCRLReason;

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
} KsbaKeyUsage;

/* X.509 certificates are represented by this object.
   ksba_cert_new() creates such an object */
struct ksba_cert_s;
typedef struct ksba_cert_s *KsbaCert;

/* CMS objects are controlled by this object.
   ksba_cms_new() creates it */
struct ksba_cms_s;
typedef struct ksba_cms_s *KsbaCMS;

/* CRL objects are controlled by this object.
   ksba_crl_new() creates it */
struct ksba_crl_s;
typedef struct ksba_crl_s *KsbaCRL;

/* PKCS-10 creation is controlled by this object.
   ksba_certreq_new() creates it */
struct ksba_certreq_s;
typedef struct ksba_certreq_s *KsbaCertreq;

/* This is a reader object vor various purposes
   see ksba_reader_new et al. */
struct ksba_reader_s;
typedef struct ksba_reader_s *KsbaReader;

/* This is a writer object vor various purposes
   see ksba_writer_new et al. */
struct ksba_writer_s;
typedef struct ksba_writer_s *KsbaWriter;

/* This is an object to store an ASN.1 parse tree as
   create by ksba_asn_parse_file() */
struct ksba_asn_tree_s;
typedef struct ksba_asn_tree_s *KsbaAsnTree;

/* This is an object to reference an General Name.  Such an object is
   returned by several functions. */
struct ksba_name_s;
typedef struct ksba_name_s *KsbaName;

/* KsbaSexp is just an unsigned char * which should be used for
   documentation purpose.  The S-expressions returned by libksba are
   always in canonical representation with an extra 0 byte at the end,
   so that one can print the values in the debugger and at least see
   the first bytes */
typedef unsigned char *KsbaSexp;
typedef const unsigned char *KsbaConstSexp;
   

/*-- cert.c --*/
KsbaCert ksba_cert_new (void);
void ksba_cert_ref (KsbaCert cert);
void     ksba_cert_release (KsbaCert cert);
KsbaError ksba_cert_read_der (KsbaCert cert, KsbaReader reader);
KsbaError ksba_cert_init_from_mem (KsbaCert cert,
                                   const void *buffer, size_t length);
const unsigned char *ksba_cert_get_image (KsbaCert cert, size_t *r_length);
KsbaError ksba_cert_hash (KsbaCert cert, int what,
                          void (*hasher)(void *,
                                         const void *,
                                         size_t length), 
                          void *hasher_arg);
const char *ksba_cert_get_digest_algo (KsbaCert cert);
KsbaSexp ksba_cert_get_serial (KsbaCert cert);
char *ksba_cert_get_issuer (KsbaCert cert, int idx);
time_t ksba_cert_get_validity (KsbaCert cert, int what);
char *ksba_cert_get_subject (KsbaCert cert, int idx);
KsbaSexp ksba_cert_get_public_key (KsbaCert cert);
KsbaSexp ksba_cert_get_sig_val (KsbaCert cert);

KsbaError ksba_cert_get_extension (KsbaCert cert, int idx,
                                   char const **r_oid, int *r_crit,
                                   size_t *r_deroff, size_t *r_derlen);

KsbaError ksba_cert_is_ca (KsbaCert cert, int *r_ca, int *r_pathlen);
KsbaError ksba_cert_get_key_usage (KsbaCert cert, unsigned int *r_flags);
KsbaError ksba_cert_get_cert_policies (KsbaCert cert, char **r_policies);
KsbaError ksba_cert_get_crl_dist_point (KsbaCert cert, int idx,
                                        KsbaName *r_distpoint,
                                        KsbaName *r_issuer,
                                        KsbaCRLReason *r_reason);
KsbaError ksba_cert_get_auth_key_id (KsbaCert cert,
                                     KsbaSexp *r_keyid,
                                     KsbaName *r_name,
                                     KsbaSexp *r_serial);


/*-- cms.c --*/
KsbaContentType ksba_cms_identify (KsbaReader reader);

KsbaCMS ksba_cms_new (void);
void    ksba_cms_release (KsbaCMS cms);
KsbaError ksba_cms_set_reader_writer (KsbaCMS cms, KsbaReader r, KsbaWriter w);

KsbaError ksba_cms_parse (KsbaCMS cms, KsbaStopReason *r_stopreason);
KsbaError ksba_cms_build (KsbaCMS cms, KsbaStopReason *r_stopreason);

KsbaContentType ksba_cms_get_content_type (KsbaCMS cms, int what);
const char *ksba_cms_get_content_oid (KsbaCMS cms, int what);
KsbaError ksba_cms_get_content_enc_iv (KsbaCMS cms, unsigned char *iv,
                                       size_t maxivlen, size_t *ivlen);
const char *ksba_cms_get_digest_algo_list (KsbaCMS cms, int idx);
KsbaError ksba_cms_get_issuer_serial (KsbaCMS cms, int idx,
                                      char **r_issuer,
                                      KsbaSexp *r_serial);
const char *ksba_cms_get_digest_algo (KsbaCMS cms, int idx);
KsbaCert ksba_cms_get_cert (KsbaCMS cms, int idx);
KsbaError ksba_cms_get_message_digest (KsbaCMS cms, int idx,
                                       char **r_digest, size_t *r_digest_len);
KsbaError ksba_cms_get_signing_time (KsbaCMS cms, int idx, time_t *r_sigtime);
KsbaSexp ksba_cms_get_sig_val (KsbaCMS cms, int idx);
KsbaSexp ksba_cms_get_enc_val (KsbaCMS cms, int idx);

void
ksba_cms_set_hash_function (KsbaCMS cms,
                            void (*hash_fnc)(void *, const void *, size_t),
                            void *hash_fnc_arg);

KsbaError ksba_cms_hash_signed_attrs (KsbaCMS cms, int idx);


KsbaError ksba_cms_set_content_type (KsbaCMS cms, int what,
                                     KsbaContentType type);
KsbaError ksba_cms_add_digest_algo (KsbaCMS cms, const char *oid);
KsbaError ksba_cms_add_signer (KsbaCMS cms, KsbaCert cert);
KsbaError ksba_cms_add_cert (KsbaCMS cms, KsbaCert cert);
KsbaError ksba_cms_set_message_digest (KsbaCMS cms, int idx,
                                       const char *digest,
                                       size_t digest_len);
KsbaError ksba_cms_set_signing_time (KsbaCMS cms, int idx, time_t sigtime);
KsbaError ksba_cms_set_sig_val (KsbaCMS cms, int idx, KsbaConstSexp sigval);

KsbaError ksba_cms_set_content_enc_algo (KsbaCMS cms,
                                         const char *oid,
                                         const unsigned char *iv,
                                         size_t ivlen);
KsbaError ksba_cms_add_recipient (KsbaCMS cms, KsbaCert cert);
KsbaError ksba_cms_set_enc_val (KsbaCMS cms, int idx, KsbaConstSexp encval);


/*-- crl.c --*/
KsbaCRL   ksba_crl_new (void);
void      ksba_crl_release (KsbaCRL crl);
KsbaError ksba_crl_set_reader (KsbaCRL crl, KsbaReader r);
void      ksba_crl_set_hash_function (KsbaCRL crl,
                            void (*hash_fnc)(void *, const void *, size_t),
                            void *hash_fnc_arg);
const char *ksba_crl_get_digest_algo (KsbaCRL crl);
KsbaError ksba_crl_get_issuer (KsbaCRL crl, char **r_issuer);
KsbaError ksba_crl_get_update_times (KsbaCRL crl, time_t *this, time_t *next);
KsbaError ksba_crl_get_item (KsbaCRL crl,
                             KsbaSexp *r_serial,
                             time_t *r_revocation_date,
                             KsbaCRLReason *r_reason);
KsbaSexp  ksba_crl_get_sig_val (KsbaCRL crl);
KsbaError ksba_crl_parse (KsbaCRL crl, KsbaStopReason *r_stopreason);

/*-- certreq.c --*/
KsbaCertreq ksba_certreq_new (void);
void      ksba_certreq_release (KsbaCertreq cr);
KsbaError ksba_certreq_set_writer (KsbaCertreq cr, KsbaWriter w);
void      ksba_certreq_set_hash_function (KsbaCertreq cr,
                               void (*hash_fnc)(void *, const void *, size_t),
                               void *hash_fnc_arg);
KsbaError ksba_certreq_add_subject (KsbaCertreq cr, const char *name);
KsbaError ksba_certreq_set_public_key (KsbaCertreq cr, KsbaConstSexp key);
KsbaError ksba_certreq_set_sig_val (KsbaCertreq cr, KsbaConstSexp sigval);
KsbaError ksba_certreq_build (KsbaCertreq cr, KsbaStopReason *r_stopreason);


/*-- reader.c --*/
KsbaReader ksba_reader_new (void);
void       ksba_reader_release (KsbaReader r);
int        ksba_reader_error (KsbaReader r);

KsbaError ksba_reader_set_mem (KsbaReader r,
                               const void *buffer, size_t length);
KsbaError ksba_reader_set_fd (KsbaReader r, int fd);
KsbaError ksba_reader_set_file (KsbaReader r, FILE *fp);
KsbaError ksba_reader_set_cb (KsbaReader r, 
                              int (*cb)(void*,char *,size_t,size_t*),
                              void *cb_value );

KsbaError ksba_reader_read (KsbaReader r,
                            char *buffer, size_t length, size_t *nread);
KsbaError ksba_reader_unread (KsbaReader r, const void *buffer, size_t count);
unsigned long ksba_reader_tell (KsbaReader r);

/*-- writer.c --*/
KsbaWriter ksba_writer_new (void);
void       ksba_writer_release (KsbaWriter r);
int ksba_writer_error (KsbaWriter w);
unsigned long ksba_writer_tell (KsbaWriter w);
KsbaError ksba_writer_set_fd (KsbaWriter w, int fd);
KsbaError ksba_writer_set_file (KsbaWriter w, FILE *fp);
KsbaError ksba_writer_set_cb (KsbaWriter w, 
                              int (*cb)(void*,const void *,size_t),
                              void *cb_value);
KsbaError ksba_writer_set_mem (KsbaWriter w, size_t initial_size);
const void *ksba_writer_get_mem (KsbaWriter w, size_t *nbytes);
void *      ksba_writer_snatch_mem (KsbaWriter w, size_t *nbytes);
KsbaError 
ksba_writer_set_filter (KsbaWriter w, 
                        KsbaError (*filter)(void*,
                                            const void *,size_t, size_t *,
                                            void *, size_t, size_t *),
                        void *filter_arg);

KsbaError ksba_writer_write (KsbaWriter w, const void *buffer, size_t length);
KsbaError ksba_writer_write_octet_string (KsbaWriter w,
                                          const void *buffer, size_t length,
                                          int flush);

/*-- asn1-parse.y --*/
int ksba_asn_parse_file (const char *filename, KsbaAsnTree *result, int debug);
void ksba_asn_tree_release (KsbaAsnTree tree);

/*-- asn1-func.c --*/
void ksba_asn_tree_dump (KsbaAsnTree tree, const char *name, FILE *fp);
KsbaError ksba_asn_create_tree (const char *mod_name, KsbaAsnTree *result);

/*-- oid.c --*/
char *ksba_oid_to_str (const char *buffer, size_t length);
int ksba_oid_from_str (const char *string, char **rbuf, size_t *rlength);


/*-- name.c --*/
KsbaName ksba_name_new (void);
void ksba_name_ref (KsbaName name);
void ksba_name_release (KsbaName name);
const char *ksba_name_enum (KsbaName name, int idx);
char *ksba_name_get_uri (KsbaName name, int idx);


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



