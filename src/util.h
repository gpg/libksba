/* util.h 
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

#ifndef UTIL_H
#define UTIL_H

#include "ksba.h"  /* ksba_malloc() etc. */

void *_ksba_xmalloc (size_t n );
void *_ksba_xcalloc (size_t n, size_t m );
void *_ksba_xrealloc (void *p, size_t n);
char *_ksba_xstrdup (const char *p);

#define xtrymalloc(a)    ksba_malloc((a))
#define xtrycalloc(a,b)  ksba_calloc((a),(b))
#define xtryrealloc(a,b) ksba_realloc((a),(b))
#define xtrystrdup(a)    ksba_strdup((a))
#define xfree(a)         ksba_free((a))

#define xmalloc(a)       _ksba_xmalloc((a))
#define xcalloc(a,b)     _ksba_xcalloc((a),(b))
#define xrealloc(a,b)    _ksba_xrealloc((a),(b))
#define xstrdup(a)       _ksba_xstrdup((a))


#define DIM(v) (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)
#ifndef STR
  #define STR(v) #v
#endif
#define STR2(v) STR(v)


#define return_if_fail(expr) do {                        \
    if (!(expr)) {                                       \
        fprintf (stderr, "%s:%d: assertion `%s' failed\n", \
                 __FILE__, __LINE__, #expr );            \
        return;	                                         \
    } } while (0)
#define return_null_if_fail(expr) do {                   \
    if (!(expr)) {                                       \
        fprintf (stderr, "%s:%d: assertion `%s' failed\n", \
                 __FILE__, __LINE__, #expr );            \
        return NULL;	                                 \
    } } while (0)
#define return_val_if_fail(expr,val) do {                \
    if (!(expr)) {                                       \
        fprintf (stderr, "%s:%d: assertion `%s' failed\n", \
                 __FILE__, __LINE__, #expr );            \
        return (val);	                                 \
    } } while (0)
#define never_reached() do {                                   \
        fprintf (stderr, "%s:%d: oops; should never get here\n", \
                 __FILE__, __LINE__ );                         \
    } while (0)


#ifndef HAVE_STPCPY
char *stpcpy (char *a, const char *b);
#endif


#endif /* UTIL_H */




