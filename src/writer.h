/* writer.h - internl definitions for the writer object.
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

#ifndef WRITER_H
#define WRITER_H 1

#include <stdio.h>

enum writer_type {
  WRITER_TYPE_NONE = 0,
  WRITER_TYPE_FD,
  WRITER_TYPE_FILE,
  WRITER_TYPE_CB
};


struct ksba_writer_s {
  int error;
  unsigned long nwritten;
  enum writer_type type;

  KsbaError (*filter)(void*,
                      const void *,size_t, size_t *,
                      void *, size_t, size_t *);
  void *filter_arg;

  union {
    struct {
      unsigned char *buffer;
      size_t size;
      size_t readpos;
    } mem;   /* for WRITER_TYPE_MEM */
    int fd;  /* for WRITER_TYPE_FD */
    FILE *file; /* for WRITER_TYPE_FILE */
    struct {
      int (*fnc)(void*,const void *,size_t);
      void *value;
    } cb;   /* for WRITER_TYPE_CB */
  } u;
};




#endif /*WRITER_H*/








