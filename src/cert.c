/* cert.c - main function for the certificate handling
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


/**
 * ksba_cert_new:
 * 
 * Create a new and empty certificate object
 * 
 * Return value: A cert object or NULL in case of memory problems.
 **/
KsbaCert
ksba_cert_new (void)
{
  KsbaCert cert;

  cert = xtrycalloc (1, sizeof *cert);
  if (!cert)
    return NULL;


  return cert;
}

/**
 * ksba_cert_release:
 * @cert: A certificate object
 * 
 * Release a certificate object.
 **/
void
ksba_cert_release (KsbaCert cert)
{
  xfree (cert);
}


/**
 * ksba_cert_read_der:
 * @cert: An unitialized certificate object
 * @reader: A KSBA Reader object
 * 
 * Read the next certificate from the reader and store it in the
 * certificate object for future access.  The certificate is parsed
 * and rejected if it has any syntactical or semantical error
 * (i.e. does not match the ASN.1 description).
 * 
 * Return value: 0 on success or an error value
 **/
KsbaError
ksba_cert_read_der (KsbaCert cert, KsbaReader reader)
{
  if (!cert || !reader)
    return KSBA_Invalid_Value;
  if (cert->initialized)
    return KSBA_Conflict;

  /* FIXME: parse it and store it in our internal format */

  return KSBA_Not_Implemented;
}





