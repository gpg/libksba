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

static void *(*alloc_func)(size_t n) = malloc;
static void *(*realloc_func)(void *p, size_t n) = realloc;
static void (*free_func)(void*) = free;


void
ksba_set_malloc_hooks ( void *(*new_alloc_func)(size_t n),
                        void *(*new_realloc_func)(void *p, size_t n),
                        void (*new_free_func)(void*) )
{
  alloc_func	    = new_alloc_func;
  realloc_func      = new_realloc_func;
  free_func	    = new_free_func;
}



/* Wrapper for the common memory allocation functions.  These are here
   so that we can add hooks.  The corresponding macros should be used.
   These macros are not named xfoo() because this name is commonly
   used for function which die on errror.  We use macronames like
   xtryfoo() instead. */

void *
ksba_malloc (size_t n )
{
  return alloc_func (n);
}

void *
ksba_calloc (size_t n, size_t m )
{
  void *p = ksba_malloc (n*m);
  if (p)
    memset (p, 0, n*m);
  return p;
}

void *
ksba_realloc (void *mem, size_t n)
{
  return realloc_func (mem, n );
}


char *
ksba_strdup (const char *str)
{
  char *p = ksba_malloc (strlen(str)+1);
  if (p)
    strcpy (p, str);
  return p;
}


void 
ksba_free ( void *a )
{
  if (a)
    free_func (a);
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
  void *p = ksba_malloc (n);
  if (!p)
    out_of_core();
  return p;
}

void *
_ksba_xcalloc (size_t n, size_t m )
{
  void *p = ksba_calloc (n,m);
  if (!p)
    out_of_core();
  return p;
}

void *
_ksba_xrealloc (void *mem, size_t n)
{
  void *p = ksba_realloc (mem,n);
  if (!p)
    out_of_core();
  return p;
}


char *
_ksba_xstrdup (const char *str)
{
  char *p = ksba_strdup (str);
  if (!p)
    out_of_core();
  return p;
}


#ifndef HAVE_STPCPY
char *
stpcpy (char *a,const char *b)
{
  while (*b)
    *a++ = *b++;
  *a = 0;

  return a;
}
#endif

