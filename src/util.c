/* util.c
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

/* Wrapper for the common memory allocation functions.  These are here
   so that we can add hooks.  The corresponding macros shoudl be used.
   These macros are not named xfoo() because this name is commonly
   used for function which die on errror.  We use macronames like
   xtryfoo() instead. */

void *
_ksba_malloc (size_t n )
{
  return malloc (n);
}

void *
_ksba_calloc (size_t n, size_t m )
{
  return calloc (n, m);
}

void *
_ksba_realloc (void *p, size_t n)
{
  return realloc (p, n );
}


char *
_ksba_strdup (const char *p)
{
  return strdup (p);
}


void 
_ksba_free ( void *a )
{
  free (a);
}


static void
out_of_core(void)
{
  fputs ("\nfatal: out of memory\n", stderr );
  exit (2);
}


/* Implementations of the common xfoo() memory allocation functions */
void *
_ksba_xmalloc (size_t n )
{
  void *p = _ksba_malloc (n);
  if (!p)
    out_of_core();
  return p;
}

void *
_ksba_xcalloc (size_t n, size_t m )
{
  void *p = _ksba_calloc (n,m);
  if (!p)
    out_of_core();
  return p;
}

void *
_ksba_xrealloc (void *p, size_t n)
{
  void *p = _ksba_realloc (p,n);
  if (!p)
    out_of_core();
  return p;
}


char *
_ksba_xstrdup (const char *p)
{
  char *p = _ksba_strdup (p);
  if (!p)
    out_of_core();
  return p;
}

