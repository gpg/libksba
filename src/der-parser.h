/* der-parser.h - Straightforward DER and TLV parser
 * Copyright (C) 2026 g10 Code GmbH
 *
 * This file is part of KSBA.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef DER_PARSER_H
#define DER_PARSER_H 1

/* The next 3 functions are only used via macros.  */
ksba_parser_t _ksba_parser_new_ (const unsigned char *buffer,
                                 size_t bufsize,
                                 int verbosity, ksba_parser_t lastparser,
                                 int lno);
ksba_parser_t _ksba_parser_release_ (ksba_parser_t tlv, int lno);
gpg_error_t _ksba_parser_next_ (ksba_parser_t tlv, int lno);

void _ksba_parser_skip (ksba_parser_t tlv);

size_t _ksba_parser_getnumber (ksba_parser_t tlv, ksba_parser_info_t what);
const char *_ksba_parser_getstring (ksba_parser_t tlv, ksba_parser_info_t what);
void _ksba_parser_setflag (ksba_parser_t tlv, ksba_parser_info_t flag);

gpg_error_t _ksba_expect_sequence (ksba_parser_t tlv);
gpg_error_t _ksba_expect_context_tag (ksba_parser_t tlv, int *r_tag);
gpg_error_t _ksba_expect_set (ksba_parser_t tlv);
gpg_error_t _ksba_expect_object (ksba_parser_t tlv, int class, int tag,
                                 unsigned char const **r_data,
                                 size_t *r_datalen);
gpg_error_t _ksba_expect_octet_string (ksba_parser_t tlv,
                                       unsigned char const **r_data,
                                       size_t *r_datalen);
gpg_error_t _ksba_expect_integer (ksba_parser_t tlv, int *r_value);
gpg_error_t _ksba_expect_object_id (ksba_parser_t tlv,
                                    unsigned char const **r_oid,
                                    size_t *r_oidlen);
gpg_error_t _ksba_expect_null (ksba_parser_t tlv);

gpg_error_t _ksba_parse_tag (unsigned char const **buffer, size_t *size,
                             ksba_tlv_t result, const char **r_errstring);




#endif /*DER_PARSER_H*/
