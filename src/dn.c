/* dn.c - Distinguished Name helper functions
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

/* Reference is RFC-2253 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "asn1-func.c"

struct {
  const char *name;
  const char *description;
  int                  oidlen;
  const unsigned char *oid;
} oid_name_tbl[] = {
{"CN", "commonName",            5, "\x06\x03\x55\x04\x03"}, /* 2.5.4.3 */
{"C",  "countryName",           5, "\x06\x03\x55\x04\x06"}, /* 2.5.4.6 */
{"L" , "localityName",          5, "\x06\x03\x55\x04\x07"}, /* 2.5.4.7 */
{"ST", "stateOrProvinceName",   5, "\x06\x03\x55\x04\x08"}, /* 2.5.4.8 */
{"STREET", "streetAddress",     5, "\x06\x03\x55\x04\x09"}, /* 2.5.4.9 */
{"O",  "organizationName",      5, "\x06\x03\x55\x04\x0a"}, /* 2.5.4.10 */
{"OU", "organizationalUnitName",5, "\x06\x03\x55\x04\x0b"}, /* 2.5.4.11 */
{"DC", "domainComponent",      12, 
       "\x06\x0a\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x01"},
                            /* 0.9.2342.19200300.100.1.25 */
/* {"UID","userid",}  FIXME: I don't have the OID  it might be ...100.1.1 */
{ NULL }
};



char *
_ksba_dn_to_str (AsnNode node)
{
  
}


int
ksba_dn_from_str (const char *string, char **rbuf, size_t *rlength)
{
}






