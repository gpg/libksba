/* ber-help.h - Basic Encoding Rules helpers
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


KsbaError _ksba_ber_read_tl (KsbaReader reader, struct tag_info *ti);


#endif /*BER_HELP_H*/

