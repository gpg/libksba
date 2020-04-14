/* ber-help.h - Basic Encoding Rules helpers
 * Copyright (C) 2001, 2012 g10 Code GmbH
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

#ifndef BER_HELP_H
#define BER_HELP_H 1


struct tag_info {
  enum tag_class class;
  int is_constructed;
  unsigned long tag;
  unsigned long length;  /* length part of the TLV */
  int ndef;              /* It is an indefinite length */
  size_t nhdr;           /* number of bytes in the TL */
  unsigned char buf[10]; /* buffer for the TL */
  const char *err_string;
  int non_der;
};


gpg_error_t _ksba_ber_read_tl (ksba_reader_t reader, struct tag_info *ti);
gpg_error_t _ksba_ber_parse_tl (unsigned char const **buffer, size_t *size,
                                struct tag_info *ti);
gpg_error_t _ksba_ber_write_tl (ksba_writer_t writer,
                                unsigned long tag,
                                enum tag_class class,
                                int constructed,
                                unsigned long length);
size_t _ksba_ber_encode_tl (unsigned char *buffer,
                            unsigned long tag,
                            enum tag_class class,
                            int constructed,
                            unsigned long length);
size_t _ksba_ber_count_tl (unsigned long tag,
                           enum tag_class class,
                           int constructed,
                           unsigned long length);


static inline void
parse_skip (unsigned char const **buf, size_t *len, struct tag_info *ti)
{
  if (ti->length)
    {
      assert (ti->length <= *len);
      *len -= ti->length;
      *buf += ti->length;
    }
}

gpg_error_t _ksba_parse_sequence (unsigned char const **buf, size_t *len,
                                  struct tag_info *ti);
#define parse_sequence(buf,len,ti) \
  _ksba_parse_sequence ((buf),(len),(ti))

gpg_error_t _ksba_parse_context_tag (unsigned char const **buf, size_t *len,
                                     struct tag_info *ti, int tag);
#define parse_context_tag(buf,len,ti,tag) \
  _ksba_parse_context_tag ((buf),(len),(ti),(tag))

gpg_error_t _ksba_parse_enumerated (unsigned char const **buf, size_t *len,
                                    struct tag_info *ti, size_t maxlen);
#define parse_enumerated(buf,len,ti,maxlen) \
  _ksba_parse_enumerated ((buf),(len),(ti),(maxlen))

gpg_error_t _ksba_parse_integer (unsigned char const **buf, size_t *len,
                                 struct tag_info *ti);
#define parse_integer(buf,len,ti) \
  _ksba_parse_integer ((buf),(len),(ti))

gpg_error_t _ksba_parse_octet_string (unsigned char const **buf, size_t *len,
                                      struct tag_info *ti);
#define parse_octet_string(buf,len,ti) \
  _ksba_parse_octet_string ((buf),(len),(ti))

gpg_error_t _ksba_parse_optional_boolean (unsigned char const **buf,
                                          size_t *len, int *r_bool);
#define parse_optional_boolean(buf,len,r_bool) \
  _ksba_parse_optional_boolean ((buf),(len),(r_bool))

gpg_error_t _ksba_parse_optional_null (unsigned char const **buf, size_t *len,
                                       int *r_seen);
#define parse_optional_null(buf,len,r_seen) \
  _ksba_parse_optional_null ((buf),(len),(r_seen))

gpg_error_t _ksba_parse_object_id_into_str (unsigned char const **buf,
                                            size_t *len, char **oid);
#define parse_object_id_into_str(buf,len,r_oid) \
  _ksba_parse_object_id_into_str ((buf),(len),(r_oid))


gpg_error_t _ksba_parse_asntime_into_isotime (unsigned char const **buf,
                                              size_t *len,
                                              ksba_isotime_t isotime);
#define parse_asntime_into_isotime(buf,len,isotime) \
  _ksba_parse_asntime_into_isotime ((buf),(len),(isotime))



#endif /*BER_HELP_H*/
