/* writer.c - provides the Writer object
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
#include "writer.h"
#include "asn1-func.h"
#include "ber-help.h"

/**
 * ksba_writer_new:
 * 
 * Create a new but uninitialized KsbaWriter Object.  Using this
 * write object in unitialized state does always return an error.
 * 
 * Return value: KsbaWriter Object or NULL in case of memory shortage.
 **/
KsbaWriter
ksba_writer_new (void)
{
  KsbaWriter w;

  w = xtrycalloc (1, sizeof *w);
  if (!w)
    return NULL;

  return w;
}


/**
 * ksba_writer_release:
 * @w: Writer Object (or NULL)
 * 
 * Release this object
 **/
void
ksba_writer_release (KsbaWriter w)
{
  if (!w)
    return;
  if (w->type == WRITER_TYPE_MEM)
    xfree (w->u.mem.buffer);
  xfree (w);
}

int
ksba_writer_error (KsbaWriter w)
{
  return w? w->error : -1;
}

unsigned long
ksba_writer_tell (KsbaWriter w)
{
  return w? w->nwritten : 0;
}


/**
 * ksba_writer_set_fd:
 * @w: Writer object
 * @fd: file descriptor
 * 
 * Initialize the Writer object with a file descriptor, so that write
 * operations on this object are excuted on this file descriptor.
 * 
 * Return value: 
 **/
KsbaError
ksba_writer_set_fd (KsbaWriter w, int fd)
{
  if (!w || fd == -1)
    return KSBA_Invalid_Value;
  if (w->type)
    return KSBA_Conflict;

  w->error = 0;
  w->type = WRITER_TYPE_FD;
  w->u.fd = fd;

  return 0;
}

/**
 * ksba_writer_set_file:
 * @w: Writer object
 * @fp: file pointer
 * 
 * Initialize the Writer object with a stdio file pointer, so that write
 * operations on this object are excuted on this stream
 * 
 * Return value: 
 **/
KsbaError
ksba_writer_set_file (KsbaWriter w, FILE *fp)
{
  if (!w || !fp)
    return KSBA_Invalid_Value;
  if (w->type)
    return KSBA_Conflict;

  w->error = 0;
  w->type = WRITER_TYPE_FILE;
  w->u.file = fp;
  return 0;
}



/**
 * ksba_writer_set_cb:
 * @w: Writer object
 * @cb: Callback function
 * @cb_value: Value passed to the callback function
 * 
 * Initialize the writer object with a callback function.
 * This callback function is defined as:
 * <literal>
 * typedef int (*cb) (void *cb_value, 
 *                    const void *buffer, size_t count);
 * </literal>
 *
 * The callback is expected to process all @count bytes from @buffer
 * @count should not be 0 and @buffer should not be %NULL
 * The callback should return 0 on success or an %KSBA_xxx error code.
 * 
 * Return value: 0 on success or an error code
 **/
KsbaError
ksba_writer_set_cb (KsbaWriter w, 
                    int (*cb)(void*,const void *,size_t), void *cb_value )
{
  if (!w || !cb)
    return KSBA_Invalid_Value;
  if (w->type)
    return KSBA_Conflict;
  
  w->error = 0;
  w->type = WRITER_TYPE_CB;
  w->u.cb.fnc = cb;
  w->u.cb.value = cb_value;

  return 0;
}


KsbaError
ksba_writer_set_mem (KsbaWriter w, size_t initial_size)
{
  if (!w)
    return KSBA_Invalid_Value;
  if (w->type == WRITER_TYPE_MEM)
    ; /* Reuse the buffer (we ignore the initial size)*/
  else
    {
      if (w->type)
        return KSBA_Conflict;

      if (!initial_size)
        initial_size = 1024;
      
      w->u.mem.buffer = xtrymalloc (initial_size);
      if (!w->u.mem.buffer)
        return KSBA_Out_Of_Core;
      w->u.mem.size = initial_size;
      w->type = WRITER_TYPE_MEM;
    }
  w->error = 0;
  w->nwritten = 0;

  return 0;
}

/* Return the pointer to the memory and the size of it.  This pointer
   is valid as long as the writer object is valid and no write
   operations takes place (because they might reallocate the buffer).
   if NBYTES is not NULL, it will receive the number of bytes in this
   buffer which is the same value ksba_writer_tell() returns.
   
   In case of an error NULL is returned.
  */
const void *
ksba_writer_get_mem (KsbaWriter w, size_t *nbytes)
{
  if (!w || w->type != WRITER_TYPE_MEM || w->error)
    return NULL;
  if (nbytes)
    *nbytes = w->nwritten;
  return w->u.mem.buffer;
}

/* Return the the memory and the size of it.  The writer object is set
   back into the uninitalized state; i.e. one of the
   ksab_writer_set_xxx () must be used before all other operations.
   if NBYTES is not NULL, it will receive the number of bytes in this
   buffer which is the same value ksba_writer_tell() returns.
   
   In case of an error NULL is returned.  */
void *
ksba_writer_snatch_mem (KsbaWriter w, size_t *nbytes)
{
  void *p;

  if (!w || w->type != WRITER_TYPE_MEM || w->error)
    return NULL;
  if (nbytes)
    *nbytes = w->nwritten;
  p = w->u.mem.buffer;
  w->u.mem.buffer = NULL;
  w->type = 0;
  w->nwritten = 0;
  return p;
}



KsbaError
ksba_writer_set_filter (KsbaWriter w, 
                        KsbaError (*filter)(void*,
                                            const void *,size_t, size_t *,
                                            void *, size_t, size_t *),
                        void *filter_arg)
{
  if (!w)
    return KSBA_Invalid_Value;
  
  w->filter = filter;
  w->filter_arg = filter_arg;
  return 0;
}




static KsbaError
do_writer_write (KsbaWriter w, const void *buffer, size_t length)
{
  if (!w->type)
    {
      w->error = -1;
      return KSBA_General_Error;
    }
  else if (w->type == WRITER_TYPE_MEM)
    {
      if (w->error == ENOMEM)
        return KSBA_Out_Of_Core; /* it does not make sense to proceed then */

      if (w->nwritten + length > w->u.mem.size)
        {
          size_t newsize = w->u.mem.size;
          char *p;

          newsize = ((newsize + 4095)/4096)*4096;
          if (newsize < 16384)
            newsize += 4096;
          else
            newsize += 16384;
          
          p = xtryrealloc (w->u.mem.buffer, newsize);
          if (!p)
            {
              /* keep an error flag so that the user does not need to
                 check the return code of a write but instead use
                 ksba_writer_error() to check for it or even figure
                 this state out when using ksba_writer_get_mem() */
              w->error = ENOMEM;
              return KSBA_Out_Of_Core;
            }
          w->u.mem.buffer = p;
          w->u.mem.size = newsize;
        }
      memcpy (w->u.mem.buffer + w->nwritten, buffer, length);
      w->nwritten += length;
    }
  else if (w->type == WRITER_TYPE_FILE)
    {
      if (!length)
        return 0;

      if ( fwrite (buffer, length, 1, w->u.file) == 1)
        {
          w->nwritten += length;
        }
      else
        {
          w->error = errno;
          return KSBA_Write_Error;
        }
    }
  else if (w->type == WRITER_TYPE_CB)
    {
      int err = w->u.cb.fnc (w->u.cb.value, buffer, length);
      if (err)
        return err;
      w->nwritten += length;
    }
  else 
    return KSBA_Bug;
  
  return 0;
} 

/**
 * ksba_writer_write:
 * @w: Writer object
 * @buffer: A buffer with the data to be written
 * @length: The length of this buffer
 * 
 * Write @length bytes from @buffer.
 *
 * Return value: 0 on success or an error code
 **/
KsbaError
ksba_writer_write (KsbaWriter w, const void *buffer, size_t length)
{
  KsbaError err=0;

  if (!w)
    return KSBA_Invalid_Value;

  if (!buffer)
      return KSBA_Not_Implemented;

  if (w->filter)
    {
      char outbuf[4096];
      size_t nin, nout;
      const char *p = buffer;

      while (length)
        {
          err = w->filter (w->filter_arg, p, length, &nin,
                           outbuf, sizeof (outbuf), &nout);
          if (err)
            break;
          if (nin > length || nout > sizeof (outbuf))
            return KSBA_Bug; /* tsss, someone else made an error */
          err = do_writer_write (w, outbuf, nout);
          if (err)
            break;
          length -= nin;
          p += nin;
        }
    }
  else
    {
      err = do_writer_write (w, buffer, length);
    }
  
  return err;
} 

/* Write LENGTH bytes of BUFFER to W while encoding it as an BER
   encoded octet string.  With FLUSH set to 1 the octet stream will be
   terminated.  If the entire octet string is available in BUFFER it
   is a good idea to set FLUSH to 1 so that the function does not need
   to encode the string partially. */
KsbaError
ksba_writer_write_octet_string (KsbaWriter w,
                                const void *buffer, size_t length, int flush)
{
  KsbaError err = 0;

  if (!w)
    return KSBA_Invalid_Value;

  if (buffer && length)
    {
      if (!w->ndef_is_open && !flush)
        {
          err = _ksba_ber_write_tl (w, TYPE_OCTET_STRING,
                                    CLASS_UNIVERSAL, 1, 0);
          if (err)
            return err;
          w->ndef_is_open = 1;
        }

      err = _ksba_ber_write_tl (w, TYPE_OCTET_STRING,
                                CLASS_UNIVERSAL, 0, length);
      if (!err)
        err = ksba_writer_write (w, buffer, length);
    }

  if (!err && flush && w->ndef_is_open) /* write an end tag */
      err = _ksba_ber_write_tl (w, 0, 0, 0, 0);

  if (flush) /* Reset it even in case of an error. */
    w->ndef_is_open = 1;

  return err;
}



