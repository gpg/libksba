/* keyinfo.h - Parse and build a keyInfo structure
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

#ifndef KEYINFO_H
#define KEYINFO_H

KsbaError
_ksba_parse_algorithm_identifier (const unsigned char *der,
                                  size_t derlen,
                                  size_t *r_nread,
                                  char **r_oid);
KsbaError
_ksba_parse_algorithm_identifier2 (const unsigned char *der, size_t derlen,
                                   size_t *r_nread, char **r_oid,
                                   char **r_parm, size_t *r_parmlen);


KsbaError _ksba_keyinfo_to_sexp (const unsigned char *der, size_t derlen,
                                 KsbaSexp *r_string);
KsbaError _ksba_sigval_to_sexp (const unsigned char *der, size_t derlen,
                                KsbaSexp *r_string);
KsbaError _ksba_encval_to_sexp (const unsigned char *der, size_t derlen,
                                KsbaSexp *r_string);

int _ksba_node_with_oid_to_digest_algo (const unsigned char *image,
                                        AsnNode node);



#endif /*KEYINFO_H*/




