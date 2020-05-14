/* der-builder.c - Straightforward DER object builder
 * Copyright (C) 2020 g10 Code GmbH
 *
 * This file is part of KSBA.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

/* This is a new way in KSBA to build DER objects without the need and
 * overhead of using an ASN.1 module.  It further avoids a lot of error
 * checking because the error checking is delayed to the last call.
 *
 * For an example on how to use it see cms.c
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "asn1-constants.h"
#include "convert.h"
#include "ber-help.h"
#include "der-builder.h"



struct item_s
{
  short int class;
  short int tag;
  unsigned int hdrlen:4;         /* Computed size of tag+length field.  */
  unsigned int is_constructed:1; /* This is a constructed element.      */
  unsigned int verbatim:1;       /* Copy the value verbatim.            */
  unsigned int is_stop:1;        /* This is a STOP item.                */
  const void *value;
  size_t valuelen;
  char *buffer;                  /* Malloced space or NULL.  */
};


/* Our DER context object; it may eventually be extended to also
 * feature a parser.  */
struct ksba_der_s
{
  gpg_error_t error;      /* Last error.  */
  size_t nallocateditems; /* Number of allocated items.  */
  size_t nitems;          /* Number of used items.  */
  struct item_s *items;   /* Array of items.  */
  int laststop;           /* Used as return value of compute_length.  */
  unsigned int finished:1;/* The object has been constructed.  */
};


/* Release a DER object.  */
void
_ksba_der_release (ksba_der_t d)
{
  int idx;

  if (!d)
    return;

  for (idx=0; idx < d->nitems; idx++)
    xfree (d->items[idx].buffer);
  xfree (d->items);
  xfree (d);
}


/* Allocate a new DER builder instance.  Returns NULL on error.
 * NITEMS can be used to tell the number of DER items needed so to
 * reduce the number of automatic reallocations.  */
ksba_der_t
_ksba_der_builder_new (unsigned int nitems)
{
  ksba_der_t d;

  d = xtrycalloc (1, sizeof *d);
  if (!d)
    return NULL;
  if (nitems)
    {
      d->nallocateditems = nitems;
      d->items = xtrycalloc (d->nallocateditems, sizeof *d->items);
      if (!d->items)
        {
          xfree (d);
          return NULL;
        }
    }

  return d;
}


/* Reset a DER build context so that a new sequence can be build.  */
void
_ksba_der_builder_reset (ksba_der_t d)
{
  int idx;

  if (!d)
    return;  /* Oops.  */
  for (idx=0; idx < d->nitems; idx++)
    {
      if (d->items[idx].buffer)
        {
          xfree (d->items[idx].buffer);
          d->items[idx].buffer = NULL;
        }
      d->items[idx].hdrlen = 0;
      d->items[idx].is_constructed = 0;
      d->items[idx].verbatim = 0;
      d->items[idx].is_stop = 0;
      d->items[idx].value = NULL;
    }
  d->nitems = 0;
  d->finished = 0;
  d->error = 0;
}


/* Make sure the array of items is large enough for one new item.
 * Records any error in D and returns true in that case.  True is also
 * returned if D is in finished state.  */
static int
ensure_space (ksba_der_t d)
{
  struct item_s *newitems;

  if (!d || d->error || d->finished)
    return 1;

  if (d->nitems == d->nallocateditems)
    {
      d->nallocateditems += 32;
      newitems = _ksba_reallocarray (d->items, d->nitems,
                                     d->nallocateditems, sizeof *newitems);
      if (!newitems)
        d->error = gpg_error_from_syserror ();
      else
        d->items = newitems;
    }
  return !!d->error;
}


/* Add a new primitive element to the builder instance D.  The element
 * is described by CLASS, TAG, VALUE, and VALUELEN.  CLASS and TAG
 * must describe a primitive element and (VALUE,VALUELEN) specify its
 * value.  The value is a pointer and its object must not be changed
 * as long as the instance D exists.  For a TYPE_NULL tag no value is
 * expected.  Errors are not returned but recorded for later
 * retrieval.  */
void
_ksba_der_add_ptr (ksba_der_t d, int class, int tag,
                   void *value, size_t valuelen)
{
  if (ensure_space (d))
    return;
  d->items[d->nitems].class    = class;
  d->items[d->nitems].tag      = tag;
  d->items[d->nitems].value    = value;
  d->items[d->nitems].valuelen = valuelen;
  d->nitems++;
}


/* This is a low level function which assumes that D has been
 * validated, VALUE is not NULL and enough space for a new item is
 * available.  It takes ownership of VALUE.  VERBATIM is usually
 * passed as false */
static void
add_val_core (ksba_der_t d, int class, int tag, void *value, size_t valuelen,
              int verbatim)
{
  d->items[d->nitems].buffer   = value;
  d->items[d->nitems].class    = class;
  d->items[d->nitems].tag      = tag;
  d->items[d->nitems].value    = value;
  d->items[d->nitems].valuelen = valuelen;
  d->items[d->nitems].verbatim = !!verbatim;
  d->nitems++;
}


/* This is the same as ksba_der_add_ptr but it takes a copy of the
 * value and thus the caller does not need to care about keeping the
 * value.  */
void
_ksba_der_add_val (ksba_der_t d, int class, int tag,
                   const void *value, size_t valuelen)
{
  void *p;

  if (ensure_space (d))
    return;
  if (!value || !valuelen)
    {
      d->error = gpg_error (GPG_ERR_INV_VALUE);
      return;
    }
  p = xtrymalloc (valuelen);
  if (!p)
    {
      d->error = gpg_error_from_syserror ();
      return;
    }
  memcpy (p, value, valuelen);
  add_val_core (d, class, tag, p, valuelen, 0);
}


/* Add an OBJECT ID element to D.  The OID is given in decimal dotted
 * format as OIDSTR.  */
void
_ksba_der_add_oid (ksba_der_t d, const char *oidstr)
{
  gpg_error_t err;
  unsigned char *buf;
  size_t len;

  if (ensure_space (d))
    return;

  err = ksba_oid_from_str (oidstr, &buf, &len);
  if (err)
    d->error = err;
  else
    add_val_core (d, 0, TYPE_OBJECT_ID, buf, len, 0);
}


/* Add a BIT STRING to D.  Using a separate function allows to easily
 * pass the number of unused bits.  */
void
_ksba_der_add_bts (ksba_der_t d, const void *value, size_t valuelen,
                   unsigned int unusedbits)
{
  unsigned char *p;

  if (ensure_space (d))
    return;
  if (!value || !valuelen || unusedbits > 7)
    {
      d->error = gpg_error (GPG_ERR_INV_VALUE);
      return;
    }
  p = xtrymalloc (1+valuelen);
  if (!p)
    {
      d->error = gpg_error_from_syserror ();
      return;
    }
  p[0] = unusedbits;
  memcpy (p+1, value, valuelen);
  add_val_core (d, 0, TYPE_BIT_STRING, p, 1+valuelen, 0);
}


/* Add (VALUE, VALUELEN) as an INTEGER to D.  If FORCE_POSITIVE iset
 * set a 0 or positive number is stored regardless of what is in
 * (VALUE, VALUELEN).  */
void
_ksba_der_add_int (ksba_der_t d, const void *value, size_t valuelen,
                   int force_positive)
{
  unsigned char *p;
  int need_extra;

  if (ensure_space (d))
    return;
  if (!value || !valuelen)
    need_extra = 1;  /* Assume the integer value 0 was meant.  */
  else
    need_extra = (force_positive && (*(const unsigned char*)value & 0x80));

  p = xtrymalloc (need_extra+valuelen);
  if (!p)
    {
      d->error = gpg_error_from_syserror ();
      return;
    }
  if (need_extra)
    p[0] = 0;
  if (valuelen)
    memcpy (p+need_extra, value, valuelen);
  add_val_core (d, 0, TYPE_INTEGER, p, need_extra+valuelen, 0);
}


/* This function allows to add a pre-constructed DER object to the
 * builder.  It should be a valid DER object but its values is not
 * further checked and copied verbatim to the final DER object
 * constructed for the handle D.  */
void
_ksba_der_add_der (ksba_der_t d, const void *der, size_t derlen)
{
  void *p;

  if (ensure_space (d))
    return;
  if (!der || !derlen)
    {
      d->error = gpg_error (GPG_ERR_INV_VALUE);
      return;
    }
  p = xtrymalloc (derlen);
  if (!p)
    {
      d->error = gpg_error_from_syserror ();
      return;
    }
  memcpy (p, der, derlen);
  add_val_core (d, 0, 0, p, derlen, 1);
}


/* Add a new constructed object to the builder instance D.  The object
 * is described by CLASS and TAG which must describe a constructed
 * object.  The elements of the constructed objects are added with
 * more call using the add functions.  To close a constructed element
 * a call to tlv_builer_add_end is required.  Errors are not returned
 * but recorded for later retrieval.  */
void
_ksba_der_add_tag (ksba_der_t d, int class, int tag)
{
  if (ensure_space (d))
    return;
  d->items[d->nitems].class    = class;
  d->items[d->nitems].tag      = tag;
  d->items[d->nitems].is_constructed = 1;
  d->nitems++;
}


/* A call to this function closes a constructed element.  This must be
 * called even for an empty constructed element.  */
void
_ksba_der_add_end (ksba_der_t d)
{
  if (ensure_space (d))
    return;
  d->items[d->nitems].is_stop = 1;
  d->nitems++;
}


/* Return the length of the TL header of a to be constructed TLV.
 * LENGTH gives the length of the value, if it is 0 indefinite length
 * is assumed.  LENGTH is ignored for the NULL tag.  TAG must be less
 * than 0x1f.  On error 0 is returned.  Note that this function is
 * similar to _ksba_ber_count_tl but we want our own copy here.  Note
 * that the returned length is always less than 16 and can thus be
 * storred in a few bits.  */
static unsigned int
count_tl (int class, int tag, size_t length)
{
  unsigned int hdrlen = 0;
  int i;

  if (tag < 0x1f)
    hdrlen++;
  else
    return 0;

  if (!tag && !class)
    hdrlen++; /* end tag */
  else if (tag == TYPE_NULL && !class)
    hdrlen++; /* NULL tag */
  else if (!length)
    hdrlen++; /* indefinite length */
  else if (length < 128)
    hdrlen++;
  else
    {
      i = (length <= 0xff ? 1:
           length <= 0xffff ? 2:
           length <= 0xffffff ? 3: 4);

      hdrlen++;
      if (i > 3)
        hdrlen++;
      if (i > 2)
        hdrlen++;
      if (i > 1)
        hdrlen++;
      hdrlen++;
    }

  return hdrlen;
}


/* Write TAG of CLASS to BUFFER.  CONSTRUCTED is a flag telling
 * whether the value is constructed.  LENGTH gives the length of the
 * value, if it is 0 undefinite length is assumed.  LENGTH is ignored
 * for the NULL tag.  TAG must be less that 0x1f.  The caller must
 * make sure that the written TL field does not overflow the
 * buffer.  */
static void
write_tl (unsigned char *buffer, int class, int tag,
          int constructed, size_t length)
{
  int i;

  if (tag < 0x1f)
    {
      *buffer = (class << 6) | tag;
      if (constructed)
        *buffer |= 0x20;
      buffer++;
    }
  else
    {
      assert (!"oops");
    }

  if (!tag && !class)
    *buffer++ = 0; /* end tag */
  else if (tag == TYPE_NULL && !class)
    *buffer++ = 0; /* NULL tag */
  else if (!length)
    *buffer++ = 0x80; /* indefinite length */
  else if (length < 128)
    *buffer++ = length;
  else
    {
      /* If we know the sizeof a size_t we could support larger
       * objects - however this is pretty ridiculous */
      i = (length <= 0xff ? 1:
           length <= 0xffff ? 2:
           length <= 0xffffff ? 3: 4);

      *buffer++ = (0x80 | i);
      if (i > 3)
        *buffer++ = length >> 24;
      if (i > 2)
        *buffer++ = length >> 16;
      if (i > 1)
        *buffer++ = length >> 8;
      *buffer++ = length;
    }
}


/* Compute and set the length of all constructed elements in the item
 * array of D starting at IDX up to the corresponding stop item.  On
 * error d->error is set.  */
static size_t
compute_lengths (ksba_der_t d, int idx)
{
  size_t total = 0;

  if (d->error)
    return 0;

  for (; idx < d->nitems; idx++)
    {
      if (d->items[idx].is_stop)
        {
          d->laststop = idx;
          break;
        }
      if (d->items[idx].verbatim)
        {
          total += d->items[idx].valuelen;
          continue;
        }
      if (d->items[idx].is_constructed)
        {
          d->items[idx].valuelen = compute_lengths (d, idx+1);
          if (d->error)
            return 0;
          /* Note: The last processed IDX is stored at d->LASTSTOP.  */
        }
      d->items[idx].hdrlen = count_tl (d->items[idx].class,
                                       d->items[idx].tag,
                                       d->items[idx].valuelen);
      if (!d->items[idx].hdrlen)
        {
          if (d->error)
            d->error = gpg_error (GPG_ERR_ENCODING_PROBLEM);
          return 0; /* Error.  */
        }

      total += d->items[idx].hdrlen + d->items[idx].valuelen;
      if (d->items[idx].is_constructed)
        idx = d->laststop;
    }
  return total;
}


/* Return the constructed DER object at D.  On success the object is
 * stored at R_OBJ and its length at R_OBJLEN.  The caller needs to
 * release that memory.  On error NULL is stored at R_OBJ and an error
 * code is returned.  Further the number of successful calls prior to
 * the error are stored at R_OBJLEN.  Note than an error may stem from
 * any of the previous call made to this object or from constructing
 * the DER object.  If this function is called with NULL for R_OBJ
 * only the current error state is returned and no further processing
 * is done.  This can be used to figure which of the add calls induced
 * the error.
 */
gpg_error_t
_ksba_der_builder_get (ksba_der_t d, unsigned char **r_obj, size_t *r_objlen)
{
  gpg_error_t err;
  int idx;
  unsigned char *buffer = NULL;
  unsigned char *p;
  size_t bufsize, buflen;

  *r_obj = NULL;
  *r_objlen = 0;

  if (!d)
    return gpg_error (GPG_ERR_INV_ARG);
  if (d->error)
    {
      err = d->error;
      if (r_objlen)
        *r_objlen = d->nitems;
      goto leave;
    }
  if (!r_obj)
    return 0;

  if (!d->finished)
    {
      if (d->nitems == 1)
        ;  /* Single item does not need an end tag.  */
      else if (!d->nitems || !d->items[d->nitems-1].is_stop)
        {
          err = gpg_error (GPG_ERR_NO_OBJ);
          goto leave;
        }

      compute_lengths (d, 0);
      err = d->error;
      if (err)
        goto leave;

      d->finished = 1;
    }

  /* If the first element is a primitive element we rightly assume no
   * other elements follow.  It is the user's duty to build a valid
   * ASN.1 object.  */
  bufsize = d->items[0].hdrlen + d->items[0].valuelen;

  /* for (idx=0; idx < d->nitems; idx++) */
  /*   gpgrt_log_debug ("DERB[%2d]: c=%d t=%2d %s p=%p h=%u l=%zu\n", */
  /*                    idx, */
  /*                    d->items[idx].class, */
  /*                    d->items[idx].tag, */
  /*                    d->items[idx].verbatim? "verbatim": */
  /*                    d->items[idx].is_stop? "stop": */
  /*                    d->items[idx].is_constructed? "cons":"prim", */
  /*                    d->items[idx].value, */
  /*                    d->items[idx].hdrlen, */
  /*                    d->items[idx].valuelen); */

  buffer = xtrymalloc (bufsize);
  if (!buffer)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  buflen = 0;
  p = buffer;

  for (idx=0; idx < d->nitems; idx++)
    {
      if (d->items[idx].is_stop)
        continue;
      if (!d->items[idx].verbatim)
        {
          if (buflen + d->items[idx].hdrlen > bufsize)
            {
              err = gpg_error (GPG_ERR_BUG);
              goto leave;
            }
          write_tl (p, d->items[idx].class, d->items[idx].tag,
                    d->items[idx].is_constructed, d->items[idx].valuelen);
          p += d->items[idx].hdrlen;
          buflen += d->items[idx].hdrlen;
        }
      if (d->items[idx].value)
        {
          if (buflen + d->items[idx].valuelen > bufsize)
            {
              err = gpg_error (GPG_ERR_BUG);
              goto leave;
            }
          memcpy (p, d->items[idx].value, d->items[idx].valuelen);
          p += d->items[idx].valuelen;
          buflen += d->items[idx].valuelen;
        }
    }
  assert (buflen == bufsize);

  *r_obj = buffer;
  *r_objlen = buflen;
  buffer = NULL;

 leave:
  xfree (buffer);
  return err;
}
