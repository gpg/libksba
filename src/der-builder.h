/* der-builder.h - Straightforward DER object builder
 * Copyright (C) 2020 g10 Code GmbH
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

#ifndef DER_BUILDER_H
#define DER_BUILDER_H 1

struct ksba_der_s;
typedef struct ksba_der_s *ksba_der_t;

/* A generic release function.  If we add a DER parser we will use the
 * same object and then it does not make sense to have several release
 * functions.  */
void       _ksba_der_release (ksba_der_t hd);

/* Create a new builder context.  */
ksba_der_t _ksba_der_builder_new (unsigned int nitems);
/* Reset a builder context.  */
void _ksba_der_builder_reset (ksba_der_t d);

void _ksba_der_add_ptr (ksba_der_t d, int class, int tag,
                        void *value, size_t valuelen);
void _ksba_der_add_val (ksba_der_t d, int class, int tag,
                        const void *value, size_t valuelen);
void _ksba_der_add_oid (ksba_der_t d, const char *oidstr);
void _ksba_der_add_bts (ksba_der_t d, const void *value, size_t valuelen,
                        unsigned int unusedbits);
void _ksba_der_add_int (ksba_der_t d, const void *value, size_t valuelen,
                        int force_positive);
void _ksba_der_add_der (ksba_der_t d, const void *der, size_t derlen);
void _ksba_der_add_tag (ksba_der_t d, int class, int tag);
void _ksba_der_add_end (ksba_der_t d);

gpg_error_t _ksba_der_builder_get (ksba_der_t d,
                                   unsigned char **r_obj, size_t *r_objlen);


#endif /*DER_BUILDER_H*/
