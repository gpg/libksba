/* reader.c - provides the Reader object
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
#include <errno.h>
#include "util.h"

#include "ksba.h"
#include "reader.h"

/**
 * ksba_reader_new:
 * 
 * Create a new but uninitialized KsbaReader Object.  Using this
 * reader object in unitialized state does always yield eof.
 * 
 * Return value: KsbaReader Object or NULL in case of memory shortage.
 **/
KsbaReader
ksba_reader_new (void)
{
  KsbaReader r;

  r = xtrycalloc (1, sizeof *r);
  if (!r)
    return NULL;

  return r;
}


/**
 * ksba_reader_release:
 * @r: Reader Object (or NULL)
 * 
 * Release this object
 **/
void
ksba_reader_release (KsbaReader r)
{
  if (r)
    return;
  xfree (r->unread.buf);
  xfree (r);
}

int
ksba_reader_error (KsbaReader r)
{
  return r? r->error : -1;
}

unsigned long
ksba_reader_tell (KsbaReader r)
{
  return r? r->nread : 0;
}


/**
 * ksba_reader_set_mem:
 * @r: Reader object
 * @buffer: Data
 * @length: Length of Data (bytes)
 * 
 * Intialize the reader object with @length bytes from @buffer and set
 * the read position to the beginning.  It is possible to reuse this
 * reader object with another buffer if the reader object has
 * already been initialized using this function.
 * 
 * Return value: 0 on success or an error code.
 **/
KsbaError
ksba_reader_set_mem (KsbaReader r, const void *buffer, size_t length)
{
  if (!r || !buffer)
    return KSBA_Invalid_Value;
  if (r->type == READER_TYPE_MEM)
    { /* Reuse this reader */
      xfree (r->u.mem.buffer);
      r->type = 0;
    }
  if (r->type)
    return KSBA_Conflict;

  r->u.mem.buffer = xtrymalloc (length);
  if (!r->u.mem.buffer)
    return KSBA_Out_Of_Core;
  memcpy (r->u.mem.buffer, buffer, length);
  r->u.mem.size = length;
  r->u.mem.readpos = 0;
  r->type = READER_TYPE_MEM;
  r->eof = 0;

  return 0;
}


/**
 * ksba_reader_set_fd:
 * @r: Reader object
 * @fd: file descriptor
 * 
 * Initialize the Reader object with a file descriptor, so that read
 * operations on this object are excuted on this file descriptor.
 * 
 * Return value: 
 **/
KsbaError
ksba_reader_set_fd (KsbaReader r, int fd)
{
  if (!r || fd == -1)
    return KSBA_Invalid_Value;
  if (r->type)
    return KSBA_Conflict;

  r->eof = 0;
  r->type = READER_TYPE_FD;
  r->u.fd = fd;

  return 0;
}

/**
 * ksba_reader_set_file:
 * @r: Reader object
 * @fp: file pointer
 * 
 * Initialize the Reader object with a stdio file pointer, so that read
 * operations on this object are excuted on this stream
 * 
 * Return value: 
 **/
KsbaError
ksba_reader_set_file (KsbaReader r, FILE *fp)
{
  if (!r || !fp)
    return KSBA_Invalid_Value;
  if (r->type)
    return KSBA_Conflict;

  r->eof = 0;
  r->type = READER_TYPE_FILE;
  r->u.file = fp;
  return 0;
}



/**
 * ksba_reader_set_cb:
 * @r: Reader object
 * @cb: Callback function
 * @cb_value: Value passed to the callback function
 * 
 * Initialize the reader object with a callback function.
 * This callback function is defined as:
 * <literal>
 * typedef int (*cb) (void *cb_value, 
 *                    char *buffer, size_t count,
 *                    size_t *nread);
 * </literal>
 *
 * The callback should return a maximium of @count bytes in @buffer
 * and the number actually read in @nread.  It may return 0 in @nread
 * if there are no bytes currently available.  To indicate EOF the
 * callback should return with an error code of %-1 and set @nread to
 * 0.  The callback may support passing %NULL for @buffer and @nread
 * and %0 for count as an indication to reset its internal read
 * pointer.
 * 
 * Return value: 0 on success or an error code
 **/
KsbaError
ksba_reader_set_cb (KsbaReader r, 
                    int (*cb)(void*,char *,size_t,size_t*), void *cb_value )
{
  if (!r || !cb)
    return KSBA_Invalid_Value;
  if (r->type)
    return KSBA_Conflict;
  
  r->eof = 0;
  r->type = READER_TYPE_CB;
  r->u.cb.fnc = cb;
  r->u.cb.value = cb_value;

  return 0;
}


/**
 * ksba_reader_read:
 * @r: Readder object
 * @buffer: A buffer for returning the data
 * @length: The length of this buffer
 * @nread:  Number of bytes actually read.
 * 
 * Read data from the current read position to the supplied @buffer,
 * max. @length bytes are read and the actual number of bytes read are
 * returned in @nread.  If there are no more bytes available %-1 is
 * returned and @nread is set to 0.
 *
 * If a @buffer of NULL is specified, the function does only return
 * the number of bytes available and does not move the read pointer.
 * This does only work for objects initialized from memory; if the
 * object is not capable of this it will return the error
 * %KSBA_Not_Implemented
 * 
 * Return value: 0 on success, -1 on EOF or an error code
 **/
KsbaError
ksba_reader_read (KsbaReader r, char *buffer, size_t length, size_t *nread)
{
  size_t nbytes;

  if (!r || !nread)
    return KSBA_Invalid_Value;


  if (!buffer)
    {
      if (r->type != READER_TYPE_MEM)
        return KSBA_Not_Implemented;
      *nread = r->u.mem.size - r->u.mem.readpos;
      if (r->unread.buf)
        *nread += r->unread.length - r->unread.readpos;
      return *nread? 0 :-1;
    }

  *nread = 0;

  if (r->unread.buf && r->unread.length)
    {
      nbytes = r->unread.length - r->unread.readpos;
      if (!nbytes)
        return KSBA_Bug;
      
      if (nbytes > length)
        nbytes = length;
      memcpy (buffer, r->unread.buf + r->unread.readpos, nbytes);
      r->unread.readpos += nbytes;
      if (r->unread.readpos == r->unread.length)
        r->unread.readpos = r->unread.length = 0;
      *nread = nbytes;
      r->nread += nbytes;
      return 0;
    }


  if (!r->type)
    {
      r->eof = 1;
      return -1;
    }
  else if (r->type == READER_TYPE_MEM)
    {
      nbytes = r->u.mem.size - r->u.mem.readpos;
      if (!nbytes)
        {
          r->eof = 1;
          return -1;
        }
      
      if (nbytes > length)
        nbytes = length;
      memcpy (buffer, r->u.mem.buffer + r->u.mem.readpos, nbytes);
      *nread = nbytes;
      r->nread += nbytes;
      r->u.mem.readpos += nbytes;
    }
  else if (r->type == READER_TYPE_FILE)
    {
      int n;

      if (r->eof)
        return -1;
      
      if (!length)
        {
          *nread = 0;
          return 0;
        }

      n = fread (buffer, 1, length, r->u.file);
      if (n > 0)
        {
          r->nread += n;
          *nread = n;
        }
      else
        *nread = 0;
      if (n < length)
        {
          if (ferror(r->u.file))
              r->error = errno;
          r->eof = 1;
          if (n <= 0)
            return -1;
        }
    }
  else if (r->type == READER_TYPE_CB)
    {
      if (r->eof)
        return -1;
      
      if (r->u.cb.fnc (r->u.cb.value, buffer, length, nread))
        {
          *nread = 0;
          r->eof = 1;
          return -1;
        }
      r->nread += *nread;
    }
  else 
    return KSBA_Bug;

  return 0;
} 

KsbaError
ksba_reader_unread (KsbaReader r, const void *buffer, size_t count)
{
  if (!r || !buffer)
    return KSBA_Invalid_Value;
  if (!count)
    return 0;

  /* Make sure that we do not push more bytes back than we have read.
     Otherwise r->nread won't have a clear semantic. */
  if (r->nread < count)
    return KSBA_Conflict;
  
  if (!r->unread.buf)
    {
      r->unread.size = count + 100;
      r->unread.buf = xtrymalloc (r->unread.size);
      if (!r->unread.buf)
        return KSBA_Out_Of_Core;
      r->unread.length = count;
      r->unread.readpos = 0;
      memcpy (r->unread.buf, buffer, count);
      r->nread -= count;
    }
  else if (r->unread.length + count < r->unread.size)
    {
      memcpy (r->unread.buf+r->unread.length, buffer, count);
      r->unread.length += count;
      r->nread -= count;
    }
  else
    return KSBA_Not_Implemented; /* fixme: easy to do */

  return 0;
}



