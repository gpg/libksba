/* asn1-constants.h
 * Copyright (C) 2020 g10 Code GmbH
 *
 * This file is free software; the authors give unlimited permission
 * to copy, distribute and modify it.
 *
 * SPDX-License-Identifier: FSFUL
 */

#ifndef ASN1_CONSTANTS_H
#define ASN1_CONSTANTS_H

typedef enum {
  TYPE_NONE = 0,
  TYPE_BOOLEAN = 1,
  TYPE_INTEGER = 2,
  TYPE_BIT_STRING = 3,
  TYPE_OCTET_STRING = 4,
  TYPE_NULL = 5,
  TYPE_OBJECT_ID = 6,
  TYPE_OBJECT_DESCRIPTOR = 7,
  TYPE_EXTERNAL = 8,
  TYPE_REAL = 9,
  TYPE_ENUMERATED = 10,
  TYPE_EMBEDDED_PDV = 11,
  TYPE_UTF8_STRING = 12,
  TYPE_REALTIVE_OID = 13,
  TYPE_SEQUENCE = 16,
  TYPE_SET = 17,
  TYPE_NUMERIC_STRING = 18,
  TYPE_PRINTABLE_STRING = 19,
  TYPE_TELETEX_STRING = 20,
  TYPE_VIDEOTEX_STRING = 21,
  TYPE_IA5_STRING = 22,
  TYPE_UTC_TIME = 23,
  TYPE_GENERALIZED_TIME = 24,
  TYPE_GRAPHIC_STRING = 25,
  TYPE_VISIBLE_STRING = 26,
  TYPE_GENERAL_STRING = 27,
  TYPE_UNIVERSAL_STRING = 28,
  TYPE_CHARACTER_STRING = 29,
  TYPE_BMP_STRING = 30,
  /* the following values do not correspond to an Universal tag */
  TYPE_CONSTANT = 128,
  TYPE_IDENTIFIER,
  TYPE_TAG,
  TYPE_DEFAULT,
  TYPE_SIZE,
  TYPE_SEQUENCE_OF,
  TYPE_ANY,
  TYPE_SET_OF,
  TYPE_DEFINITIONS,
  TYPE_CHOICE,
  TYPE_IMPORTS,
  TYPE_PRE_SEQUENCE  /* premanufactured Seqences as used by the DER encoder. */
} node_type_t;


enum tag_class {
  CLASS_UNIVERSAL = 0,
  CLASS_APPLICATION = 1,
  CLASS_CONTEXT = 2,
  CLASS_PRIVATE =3
};

#endif /*ASN1_CONSTANTS_H*/
