/* cert-get.c - Get attributes from a certificate
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "util.h"

#include "ksba.h"
#include "cert.h"


KsbaError
ksba_cert_get_string_attr (KsbaCert cert, KsbaAttr what, int idx,
                           const char **ret)
{
  *ret = NULL; /* set a default value */
  if (!cert || idx < 0 )
    return KSBA_Invalid_Value;

  switch (what)
    {
      
    default:
      return KSBA_Invalid_Attr;
    }
  
  return 0;
}


/* FIXME: This function is not yet used or published. */
KsbaError
ksba_cert_get_time_attr (KsbaCert cert, KsbaAttr what, int idx,
                         ksba_isotime_t ret)
{
  *ret = 0; /* set a default value */
  if (!cert || idx < 0 )
    return KSBA_Invalid_Value;

  switch (what)
    {
      
    default:
      return KSBA_Invalid_Attr;
    }
  
  return 0;
}

