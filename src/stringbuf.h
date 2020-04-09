/* stringbuf.h - Inline functions for building strings.
 * Copyright (C) 2001, 2002, 2007, 2008, 2012, 2020 g10 Code GmbH
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

#ifndef STRINGBUF_H
#define STRINGBUF_H 1

#include "util.h"
#include "errno.h"

struct stringbuf
{
  size_t len;
  size_t size;
  char *buf;
  gpg_error_t out_of_core;
};


static inline void
init_stringbuf (struct stringbuf *sb, int initiallen)
{
  sb->len = 0;
  sb->size = initiallen;
  sb->out_of_core = 0;
  /* allocate one more, so that get_stringbuf can append a nul */
  sb->buf = xtrymalloc (initiallen+1);
  if (!sb->buf)
    sb->out_of_core = errno? errno : ENOMEM;
}


static inline void
deinit_stringbuf (struct stringbuf *sb)
{
  xfree (sb->buf);
  sb->buf = NULL;
  sb->out_of_core = ENOMEM; /* make sure the caller does an init before reuse */
}


static inline void
put_stringbuf_mem (struct stringbuf *sb, const char *text, size_t n)
{
  if (sb->out_of_core)
    return;

  if (sb->len + n >= sb->size)
    {
      char *p;

      sb->size += n + 100;
      p = xtryrealloc (sb->buf, sb->size + 1);
      if (!p)
        {
          sb->out_of_core = errno? errno : ENOMEM;
          return;
        }
      sb->buf = p;
    }
  memcpy (sb->buf+sb->len, text, n);
  sb->len += n;
}


static inline void
put_stringbuf_mem_skip (struct stringbuf *sb, const char *text, size_t n,
                        int skip)
{
  char *p;

  if (!skip)
    {
      put_stringbuf_mem (sb, text, n);
      return;
    }
  if (sb->out_of_core)
    return;

  if (sb->len + n >= sb->size)
    {
      /* Note: we allocate too much here, but we don't care. */
      sb->size += n + 100;
      p = xtryrealloc (sb->buf, sb->size + 1);
      if ( !p)
        {
          sb->out_of_core = errno? errno : ENOMEM;
          return;
        }
      sb->buf = p;
    }
  p = sb->buf+sb->len;
  while (n > skip)
    {
      text += skip;
      n -= skip;
      *p++ = *text++;
      n--;
      sb->len++;
    }
}


static inline void
put_stringbuf (struct stringbuf *sb, const char *text)
{
  put_stringbuf_mem (sb, text,strlen (text));
}


static inline void
put_stringbuf_mem_sexp (struct stringbuf *sb, const char *text, size_t length)
{
  char buf[20];
  sprintf (buf,"%u:", (unsigned int)length);
  put_stringbuf (sb, buf);
  put_stringbuf_mem (sb, text, length);
}


static inline void
put_stringbuf_sexp (struct stringbuf *sb, const char *text)
{
  put_stringbuf_mem_sexp (sb, text, strlen (text));
}


static inline void
put_stringbuf_uint (struct stringbuf *sb, unsigned int value)
{
  char buf[35];
  snprintf (buf, sizeof buf, "%u", (unsigned int)value);
  put_stringbuf_sexp (sb, buf);
}


static inline char *
get_stringbuf (struct stringbuf *sb)
{
  char *p;

  if (sb->out_of_core)
    {
      xfree (sb->buf); sb->buf = NULL;
      gpg_err_set_errno (sb->out_of_core);
      return NULL;
    }

  sb->buf[sb->len] = 0;
  p = sb->buf;
  sb->buf = NULL;
  sb->out_of_core = ENOMEM; /* make sure the caller does an init before reuse */
  return p;
}


#endif /*STRINGBUF_H*/
