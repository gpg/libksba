/* reader.h - internl definitions for the reder object.
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

#ifndef READER_H
#define READER_H 1

#include <stdio.h>

enum reader_type {
  READER_TYPE_NONE = 0,
  READER_TYPE_MEM,
  READER_TYPE_FD,
  READER_TYPE_FILE,
  READER_TYPE_CB
};


struct ksba_reader_s {
  int eof;
  int error;
  enum reader_type type;
  union {
    struct {
      unsigned char *buffer;
      size_t size;
      size_t readpos;
    } mem;   /* for READER_TYPE_MEM */
    int fd;  /* for READER_TYPE_FD */
    FILE *file; /* for READER_TYPE_FILE */
    struct {
      int (*fnc)(void*,char *,size_t,size_t*);
      void *value;
    } cb;   /* for READER_TYPE_CB */
  } u;
};




#endif /*READER_H*/

