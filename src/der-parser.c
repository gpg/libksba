/* der-parser.c - Straightforward DER and TLV parser
 * Copyright (C) 2023, 2024, 2026 g10 Code GmbH
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

/* This used to be the TLV parser of GnuPG and has been adjusted to be
 * part of KSBA.  The actual origin of the code was the minip12.c
 * module of GnuPG.  This parser is an alternative to the traditional
 * table driven BER parser of KSBA.  Although it is named DER parser,
 * it can actually handle BER.  */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "asn1-constants.h"
#include "convert.h"
#include "ber-help.h"
#include "der-parser.h"


#define TLV_MAX_DEPTH 25


/* An object to control the ASN.1 parsing.  */
struct ksba_parser_s
{
  /* The original buffer with the entire object and its length.  */
  unsigned char *origbuffer;
  size_t origbufsize;

  /* The original offset for debugging.  */
  size_t origoff;

  /* Here we keep a copy of the former TLV.  This is returned by
   * ksba_parser_release.  */
  ksba_parser_t lastparser;

  /* The current buffer we are working on and its length. */
  unsigned char *buffer;
  size_t bufsize;

  size_t crammed;         /* 0 or actual length of crammed octet strings.  */
  int in_ndef;            /* Flag indicating that we are in a NDEF. */
  unsigned int pending:1; /* The last ksba_next has not yet been processed.  */
  unsigned int t5793:1;   /* Handle Mozilla bug.  */

  struct tag_info ti;  /* The current tag.  */
  gpg_error_t lasterr; /* Last error from tlv function.  */
  const char *lastfunc;/* Name of last called function.  */
  int verbosity;       /* Arg from ksba_parser_new.       */

  unsigned int stacklen; /* Used size of the stack.  */
  struct {
    unsigned char *buffer;        /* Saved value of BUFFER.   */
    size_t bufsize;               /* Saved value of BUFSIZE.  */
    size_t length;                /* Length of the container (ti.length). */
    size_t crammed;               /* Saved CRAMMED value.                 */
    int    in_ndef;               /* Saved IN_NDEF flag (ti.ndef).        */
  } stack[TLV_MAX_DEPTH];
};


static size_t cram_octet_string (ksba_parser_t tlv, int testmode);



static void
parser_dump_tag (const char *text, int lno, ksba_parser_t tlv)
{
  struct tag_info *ti;

  if (!tlv || tlv->verbosity < 2)
    return;

  ti = &tlv->ti;

  gpgrt_log_debug ("ksba_parser:%s:%d: %zu@%04zu class=%d tag=%lu %c"
                   " len=%zu%s nhdr=%zu\n",
                   text, lno, tlv->origoff,
                   ksba_parser_getnumber (tlv, KSBA_PARSER_OFFSET) - ti->nhdr,
                   ti->class, ti->tag, ti->is_constructed?'c':'p',
                   ti->length,ti->ndef?" ndef":"", ti->nhdr);
}


static void
parser_dump_state (const char *text, const char *text2,
                   int lno, ksba_parser_t tlv)
{
  if (!tlv || tlv->verbosity < 2)
    return;

  gpgrt_log_debug ("ksba_parser:%s%s%s:%d: %zu@%04zu lvl=%u %s\n",
                   text,
                   text2? "/":"", text2? text2:"",
                   lno, tlv->origoff,
                   ksba_parser_getnumber (tlv, KSBA_PARSER_OFFSET),
                   tlv->stacklen,
                   tlv->in_ndef? " in-ndef":"");
}



static void
dump_to_file (const void *s, size_t n, const char *name)
{
  static int fcount;
  gpgrt_stream_t fp;
  char fname[100];

  if (getenv ("KSBA_DEBUG_DER_PARSER"))
    {
      snprintf (fname, sizeof fname, "tmp-ksba-%03d-%s", ++fcount, name);
      gpgrt_log_debug ("%s: dumping %zu bytes to '%s'\n", __func__, n, fname);
      fp = gpgrt_fopen (fname, "wb");
      if (!fp || gpgrt_fwrite (s, n, 1, fp) != 1)
        gpgrt_log_debug ("%s: failed to open or write to dump file\n",
                         __func__);
      gpgrt_fclose (fp);
    }
}


/* Parse the buffer at the address BUFFER which is of SIZE and return
 * the tag and the length part from the TLV triplet.  Update BUFFER
 * and SIZE on success.  Checks that the encoded length does not
 * exhaust the length of the provided buffer.  */
static int
parse_tag (unsigned char const **buffer, size_t *size, struct tag_info *ti,
           int verbose)
{
  gpg_error_t err;

  err = _ksba_ber_parse_tl (buffer, size, ti);
  if (err)
    return err;

  if (ti->length > *size)
    {
      /* Data larger than buffer. */
      if (verbose)
        gpgrt_log_debug ("%s: ti->length=%zu for a buffer of size=%zu\n",
                         __func__, ti->length, *size);
      if (!ti->err_string)
        ti->err_string = "provided buffer too short to receive the value";
      return gpg_error (GPG_ERR_BUFFER_TOO_SHORT);
    }

  return 0;
}

/* Public version of parse_tag.  Note that the name part "parse" is
 * intentionally.  On error the result structure maybe filled.  */
gpg_error_t
ksba_parse_tag (unsigned char const **buffer, size_t *size,
                ksba_tlv_t result, const char **r_errstring)
{
  gpg_error_t err;
  struct tag_info ti;

  err = parse_tag (buffer, size, &ti, 0);
  result->length = ti.length;
  result->tag = ti.tag;
  result->nhdr = ti.nhdr > 255? 255 : ti.nhdr;
  result->cls = ti.class;
  result->ndef = !!ti.ndef;
  result->cons = !!ti.is_constructed;
  result->der  = !ti.non_der;
  result->_rfu = 0;

  if (r_errstring)
    *r_errstring = ti.err_string? ti.err_string : "";

  /* Extra check because parse_tag may return a large header which is
   * only allowed in theory.  */
  if (!err && ti.nhdr > 255)
    {
      if (r_errstring)
        *r_errstring = "header too large";
      err = gpg_error (GPG_ERR_TOO_LARGE);
    }

  return err;
}


/* Create a new TLV object.  Caller should use the ksba_parser_new
 * macro.  (note the underscore suffix) */
ksba_parser_t
_ksba_parser_new_ (const unsigned char *buffer, size_t bufsize,
                   unsigned int verbosity, ksba_parser_t lastparser, int lno)
{
  ksba_parser_t tlv;

  if (verbosity > 1)
    gpgrt_log_debug ("%s:%d: %zu@%zu (%p,%zu)\n", __func__, lno,
                     lastparser?lastparser->origoff:0,
                     ksba_parser_getnumber (lastparser, KSBA_PARSER_OFFSET),
                     buffer, bufsize);

  tlv = xtrycalloc (1, sizeof *tlv);
  if (tlv)
    {
      char *mybuf = xtrymalloc ( bufsize + 1);
      if (!mybuf)
        {
          xfree (tlv);
          return NULL;
        }
      memcpy (mybuf, buffer, bufsize);
      mybuf[bufsize] = 0;
      tlv->origbuffer = mybuf;
      tlv->origbufsize = bufsize;
      tlv->origoff = ksba_parser_getnumber (lastparser, KSBA_PARSER_OFFSET);
      tlv->buffer = mybuf;
      tlv->bufsize = bufsize;
      tlv->crammed = 0;
      tlv->pending = 0;
      tlv->t5793 = 0;
      tlv->verbosity = verbosity;
      tlv->lastparser = lastparser;
      if (verbosity > 1)
        dump_to_file (mybuf, bufsize, "context");
    }
  return tlv;
}


/* Free the TLV object and returns the last TLV object stored in this
 * TLV.  Caller should use the ksba_parser_release macro.
 * (note the underscore suffix)  */
ksba_parser_t
_ksba_parser_release_ (ksba_parser_t tlv, int lno)
{
  ksba_parser_t result;

  if (!tlv)
    return NULL;
  result = tlv->lastparser;
  if (tlv->verbosity > 1)
    {
      if (result)
        gpgrt_log_debug ("%s:%d: done; returning last TLV %zu@%zu (%p,%zu)\n",
                         __func__, lno, result->origoff,
                         ksba_parser_getnumber (result, KSBA_PARSER_OFFSET),
                         result->buffer, result->bufsize);
      else
        gpgrt_log_debug ("%s:%d: done\n", __func__, lno);
    }
  xfree (tlv->origbuffer);
  xfree (tlv);
  return result;
}


/* Helper for tlv_expect_sequence and tlv_expect_context_tag.  */
static gpg_error_t
_tlv_push (ksba_parser_t tlv)
{

  /* Right now our pointer is at the value of the current container.
   * We push that info onto the stack.  */
  if (tlv->stacklen >= TLV_MAX_DEPTH)
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_MANY));
  tlv->stack[tlv->stacklen].buffer  = tlv->buffer;
  tlv->stack[tlv->stacklen].bufsize = tlv->bufsize;
  tlv->stack[tlv->stacklen].in_ndef = tlv->in_ndef;
  tlv->stack[tlv->stacklen].length  = tlv->ti.length;
  tlv->stack[tlv->stacklen].crammed = tlv->crammed;
  tlv->stacklen++;

  tlv->in_ndef = tlv->ti.ndef;

  /* We set the size of the buffer to the TLV length if it is known or
   * else to the size of the remaining entire buffer.  */
  if (tlv->in_ndef)
    {
      if ((tlv->buffer - tlv->origbuffer) > tlv->origbufsize)
        return (tlv->lasterr = gpg_error (GPG_ERR_BUG));
      tlv->bufsize = tlv->origbufsize - (tlv->buffer - tlv->origbuffer);
    }
  else
    tlv->bufsize = tlv->ti.length;

  parser_dump_state (__func__, NULL, 0, tlv);
  return 0;
}


/* Helper for tlv_next.  */
static gpg_error_t
_tlv_pop (ksba_parser_t tlv)
{
  size_t length;

  /* We reached the end of a container, either due to the size limit
   * or due to an end tag.  Now we pop the last container so that we
   * are positioned at the value of the last container. */
  if (!tlv->stacklen)
    return gpg_error (GPG_ERR_EOF);

  tlv->stacklen--;
  tlv->in_ndef = tlv->stack[tlv->stacklen].in_ndef;
  length = tlv->ti.length = tlv->stack[tlv->stacklen].length;
  tlv->crammed = tlv->stack[tlv->stacklen].crammed;
  if (tlv->in_ndef)
    {
      /* We keep buffer but adjust bufsize to the end of the origbuffer. */
      if ((tlv->buffer - tlv->origbuffer) > tlv->origbufsize)
        return (tlv->lasterr = gpg_error (GPG_ERR_BUG));
      tlv->bufsize = tlv->origbufsize - (tlv->buffer - tlv->origbuffer);
    }
  else
    {
      tlv->buffer  = tlv->stack[tlv->stacklen].buffer;
      tlv->bufsize = tlv->stack[tlv->stacklen].bufsize;
      if (length > tlv->bufsize)
        {
          if (tlv->verbosity > 1)
            gpgrt_log_debug ("%s: container larger than buffer (%zu/%zu)\n",
                             __func__, length, tlv->bufsize);
          return gpg_error (GPG_ERR_INV_BER);
        }
      tlv->buffer += length;
      tlv->bufsize -= length;

    }
  parser_dump_state (__func__, NULL, 0, tlv);
  return 0;
}


/* Parse the next tag and value.  Also detect the end of a container.
 * The caller should use the ksba_parser_next macro.
 * (note the underscrore suffix) */
gpg_error_t
_ksba_parser_next_ (ksba_parser_t tlv, int lno)
{
  gpg_error_t err;
  const unsigned char *buffer;
  size_t save_bufsize;
  const unsigned char *save_buffer;
  int i;
  int t5793_flag;

  tlv->lasterr = 0;
  tlv->lastfunc = __func__;

  /* Save a copy of a flag which is only valid for one call.  */
  t5793_flag = tlv->t5793;
  tlv->t5793 = 0;

  if (tlv->pending)
    {
      tlv->pending = 0;
      if (tlv->verbosity > 1)
        gpgrt_log_debug ("%s:%d: skipped\n", __func__, lno);
      return 0;
    }

  if (tlv->verbosity > 1)
    gpgrt_log_debug ("%s:%d: called (%p,%zu)\n", __func__, lno,
                     tlv->buffer, tlv->bufsize);
  /* If we are at the end of an ndef container pop the stack.  */
  if (!tlv->in_ndef && !tlv->bufsize)
    {
      if (tlv->verbosity > 1)
        for (i=0; i < tlv->stacklen; i++)
          gpgrt_log_debug ("%s: stack[%d] (%p,@%zu,%zu) len=%zu (%zu) %s\n",
                           __func__, i,
                           tlv->stack[i].buffer,
                           tlv->stack[i].buffer - tlv->origbuffer,
                           tlv->stack[i].bufsize,
                           tlv->stack[i].length,
                           tlv->stack[i].crammed,
                           tlv->stack[i].in_ndef? " ndef":"");
      do
        err = _tlv_pop (tlv);
      while (!err && !tlv->in_ndef && !tlv->bufsize);

      if (err)
        return (tlv->lasterr = err);
      if (tlv->verbosity > 1)
        gpgrt_log_debug ("%s: container(s) closed due to size (lvl=%d)\n",
                         __func__, tlv->stacklen);
    }

 again:
  /* Get the next tag.  */
  save_buffer = buffer = tlv->buffer;
  save_bufsize = tlv->bufsize;
  err = parse_tag (&buffer, &tlv->bufsize, &tlv->ti, tlv->verbosity);
  tlv->buffer = (unsigned char *)buffer;
  if (err)
    {
      if (tlv->verbosity > 1)
        {
          gpgrt_log_debug ("%s: reading tag returned err=%d\n", __func__, err);
          gpgrt_log_printhex (save_buffer, save_bufsize > 40? 40: save_bufsize,
                              "%s: data was\n", __func__);
          dump_to_file (tlv->origbuffer, save_buffer - tlv->origbuffer,
                        "parseerr");
        }
      return err;
    }

  if ( ( (tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TYPE_OCTET_STRING)
         || (t5793_flag && tlv->ti.class == CLASS_CONTEXT && tlv->ti.tag == 0))
       && tlv->ti.is_constructed && cram_octet_string (tlv, 1))
    {
      if (tlv->verbosity > 1)
        gpgrt_log_debug ("%s: cramming %s\n", __func__,
                         tlv->ti.tag? "constructed octet strings"
                         /* */      : "for Mozilla bug");
      if (!cram_octet_string (tlv, 0))
        return (tlv->lasterr = gpg_error (GPG_ERR_BAD_BER));
    }

  /* If there is an end tag in an ndef container pop the stack.  Also
   * pop other containers which are fully consumed. */
  if (tlv->in_ndef && (tlv->ti.class == CLASS_UNIVERSAL
                       && !tlv->ti.tag && !tlv->ti.is_constructed))
    {
      do
        err = _tlv_pop (tlv);
      while (!err && !tlv->in_ndef && !tlv->bufsize);
      if (err)
        return (tlv->lasterr = err);
      if (tlv->verbosity > 1)
        gpgrt_log_debug ("%s: container(s) closed due to end tag (lvl=%d)\n",
                         __func__, tlv->stacklen);
      goto again;
    }

  parser_dump_tag (__func__, lno, tlv);
  return 0;
}


/* Skip over the value of the current tag.  Does not yet work for ndef
 * containers.  */
void
ksba_parser_skip (ksba_parser_t tlv)
{
  tlv->lastfunc = __func__;
  if (!(tlv->bufsize >= tlv->ti.length))
    gpgrt_log_bug ("ksba:%s: bufsize=%zu length=%zu\n",
                   __func__, tlv->bufsize, tlv->ti.length);
  tlv->buffer += tlv->ti.length;
  tlv->bufsize -= tlv->ti.length;
}


/* Return an unsigned number from the TLV object.  WHAT give the
 * actual value to retrieve:
 *   KSBA_PARSER_TAGLEN    := The length of the last read tag.
 *   KSBA_PARSER_TAGLENHDR := The length of the last read tag with header.
 *   KSBA_PARSER_LEVEL     := The current recursion leve
 *   KSBA_PARSER_OFFSET    := The current offset of the parser
 *   KSBA_PARSER_LASTERR   := The last error number
 */
size_t
ksba_parser_getnumber (ksba_parser_t tlv, ksba_parser_info_t what)
{
  if (!tlv)
    return 0;
  else if (what == KSBA_PARSER_TAGLEN)
    return tlv->ti.length;
  else if (what == KSBA_PARSER_TAGLENHDR)
    return tlv->ti.length + tlv->ti.nhdr;
  else if (what == KSBA_PARSER_LEVEL)
    return tlv->stacklen;
  else if (what == KSBA_PARSER_OFFSET)
    return (size_t)(tlv->buffer - tlv->origbuffer);
  else if (what == KSBA_PARSER_LASTERR)
    return tlv->lasterr;
  else
    return 0;
}


/* Return a string from the TLV object. The string is only balid as
 * long as the TLV object exists.  WHAT give the actual value to
 * retrieve:
 *   KSBA_PARSER_LASTFUNC := The name of the last used function
 *   KSBA_PARSER_LASTERR  := The last error string
 * For unknown WHAT values an empty string is returned; NULL is never
 * returned.  */
const char *
ksba_parser_getstring (ksba_parser_t tlv, ksba_parser_info_t what)
{
  if (!tlv)
    return "tlv parser not yet initialized";
  else if (what == KSBA_PARSER_LASTFUNC)
    return tlv? tlv->lastfunc : "";
  else if (what == KSBA_PARSER_LASTERR)
    return gpg_strerror (tlv->lasterr);
  else
    return "";
}


/* Set a flag into the TLV object.
 *   KSBA_PARSER_PENDING   := Indicate that the last ksba_next has not yet
 *                            been consumed.
 *   KSBA_PARSER_T5793     := Enable workaround for Mozilla bug.
 *                            (see https://dev.gnupg.org/T5793)
 *   KSBA_PARSER_DUMPTAG   := Dump the current tag
 *   KSBA_PARSER_DUMPSTATE := Dump the current state
 */
void
ksba_parser_setflag (ksba_parser_t tlv, ksba_parser_info_t flag)
{
  if (!tlv)
    ;
  else if (flag == KSBA_PARSER_PENDING)
    tlv->pending = 1;
  else if (flag == KSBA_PARSER_T5793)
    tlv->t5793 = 1;
  else if (flag == KSBA_PARSER_DUMPTAG)
    parser_dump_tag ("", 0, tlv);
  else if (flag == KSBA_PARSER_DUMPSTATE)
    parser_dump_state ("", NULL, 0, tlv);
}


/* Expect that the current tag is a sequence and setup the context for
 * processing.  */
gpg_error_t
ksba_expect_sequence (ksba_parser_t tlv)
{
  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TYPE_SEQUENCE
        && tlv->ti.is_constructed))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  return _tlv_push (tlv);
}


/* Expect that the current tag is a context tag and setup the context
 * for processing.  The tag of the context is returned at R_TAG.  */
gpg_error_t
ksba_expect_context_tag (ksba_parser_t tlv, int *r_tag)
{
  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_CONTEXT && tlv->ti.is_constructed))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  *r_tag = tlv->ti.tag;
  return _tlv_push (tlv);
}


/* Expect that the current tag is a SET and setup the context for
 * processing.  */
gpg_error_t
ksba_expect_set (ksba_parser_t tlv)
{
  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TYPE_SET
        && tlv->ti.is_constructed))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  return _tlv_push (tlv);
}


/* Expect an object of CLASS with TAG and store its value at
 * (R_DATA,R_DATALEN).  Then skip over its value to the next tag.
 * Note that the stored value is not allocated but points into
 * TLV.  */
gpg_error_t
ksba_expect_object (ksba_parser_t tlv, int class, int tag,
                     unsigned char const **r_data, size_t *r_datalen)
{
  const unsigned char *p;
  size_t n;
  int needpush = 0;

  tlv->lastfunc = __func__;
  /* Note that the parser has already crammed the octet strings for a
   * [0] to workaround the Mozilla bug.  */
  if (!(tlv->ti.class == class && tlv->ti.tag == tag))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  p = tlv->buffer;
  n = tlv->ti.length;
  if (!n && tlv->ti.ndef)
    {
      n = tlv->bufsize;
      needpush = 1;
    }
  else if (!tlv->ti.length)
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));

  if (tlv->verbosity > 1)
    gpgrt_log_debug ("%s: %zu@%zu %c len=%zu (%zu) bufsize=%zu of %zu\n",
                     __func__,
                     tlv->origoff,
                     ksba_parser_getnumber (tlv, KSBA_PARSER_OFFSET),
                     tlv->ti.is_constructed? 'c':'p',
                     n, tlv->crammed,
                     tlv->bufsize, tlv->origbufsize);

  if (r_data)
    *r_data = p;
  if (r_datalen)
    *r_datalen = tlv->crammed? tlv->crammed : n;

  if (needpush)
    return _tlv_push (tlv);

  if (!(tlv->bufsize >= n))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));
  tlv->buffer += n;
  tlv->bufsize -= n;
  tlv->crammed = 0;
  return 0;
}


/* Expect that the current tag is an octet string and store its value
 * at (R_DATA,R_DATALEN).  Then skip over its value to the next tag.
 * Note that the stored value are not allocated but point into TLV. */
gpg_error_t
ksba_expect_octet_string (ksba_parser_t tlv,
                          unsigned char const **r_data, size_t *r_datalen)
{
  size_t n;

  tlv->lastfunc = __func__;
  /* The parser has already crammed constructed octet strings.  */
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TYPE_OCTET_STRING))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  if (!(n=tlv->ti.length) || tlv->ti.ndef )
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));

  if (tlv->verbosity > 1)
    gpgrt_log_debug ("%s: %zu@%zu %c len=%zu (%zu) bufsize=%zu of %zu\n",
                     __func__,
                     tlv->origoff,
                     ksba_parser_getnumber (tlv, KSBA_PARSER_OFFSET),
                     tlv->ti.is_constructed? 'c':'p',
                     n, tlv->crammed,
                     tlv->bufsize, tlv->origbufsize);

  if (r_data)
    *r_data = tlv->buffer;
  if (r_datalen)
    *r_datalen = tlv->crammed? tlv->crammed : tlv->ti.length;

  if (!(tlv->bufsize >= tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));
  tlv->buffer += tlv->ti.length;
  tlv->bufsize -= tlv->ti.length;
  tlv->crammed = 0;
  return 0;
}


/* Expect that the current tag is an integer and return its value at
 * R_VALUE.  Then skip over its value to the next tag. */
gpg_error_t
ksba_expect_integer (ksba_parser_t tlv, int *r_value)
{
  const unsigned char *p;
  size_t n;
  int value;

  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TYPE_INTEGER
        && !tlv->ti.is_constructed))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  p = tlv->buffer;
  if (!(n=tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));

  /* We currently support only positive values.  */
  if ((*p & 0x80))
    return (tlv->lasterr = gpg_error (GPG_ERR_ERANGE));

  for (value = 0; n; n--)
    {
      value <<= 8;
      value |= (*p++) & 0xff;
      if (value < 0)
        return (tlv->lasterr = gpg_error (GPG_ERR_EOVERFLOW));
    }
  *r_value = value;
  if (!(tlv->bufsize >= tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));
  tlv->buffer += tlv->ti.length;
  tlv->bufsize -= tlv->ti.length;
  return 0;
}


/* Expect that the current tag is an object id and store its value at
 * (R_OID,R_OIDLEN).  Then skip over its value to the next tag.  Note
 * that the stored value is not allocated but points into TLV. */
gpg_error_t
ksba_expect_object_id (ksba_parser_t tlv,
                       unsigned char const **r_oid, size_t *r_oidlen)
{
  const unsigned char *p;
  size_t n;

  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TYPE_OBJECT_ID
        && !tlv->ti.is_constructed))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  p = tlv->buffer;
  if (!(n=tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));

  *r_oid = p;
  *r_oidlen = tlv->ti.length;
  if (!(tlv->bufsize >= tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_TOO_SHORT));
  tlv->buffer += tlv->ti.length;
  tlv->bufsize -= tlv->ti.length;
  return 0;
}


/* Expect a NULL tag.  */
gpg_error_t
ksba_expect_null (ksba_parser_t tlv)
{
  tlv->lastfunc = __func__;
  if (!(tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TYPE_NULL
        && !tlv->ti.is_constructed && !tlv->ti.length))
    return (tlv->lasterr = gpg_error (GPG_ERR_INV_OBJ));
  return 0;
}


/* Given a BER encoded constructed octet string like the example below
 * from Mozilla Firefox 1.0.4 (which actually exports certs as single
 * byte chunks of octet strings) in the buffer described by TLV.
 * Although the example uses an ndef for the length of the constructed
 * octet string, a fixed length is also allowed.
 *
 *   24 NDEF:       OCTET STRING
 *   04    1:         OCTET STRING  -- TLV->buffer points to here
 *          :           30
 *   04    1:         OCTET STRING
 *          :           80
 *        [...]
 *   04    2:         OCTET STRING
 *          :           00 00
 *          :         } -- This denotes a Null tag and are the last
 *                      -- two bytes in INPUT.
 *
 * Turn it into a primitive octet string of this form:
 *
 *   24    2:       OCTET STRING
 *          :         30 80
 *
 * and fill it up with FE to the original length.  Unless TESTMODE is
 * true the TLV object including the the member and the data is
 * adjusted accordingly; however the intitial tag is not changed (in
 * the example the "24 NDEF") because this is not needed anymore.
 *
 * On error 0 is returned and in this case the buffer might have
 * already been modified and thus the caller should better stop
 * parsing - unless TESTMODE was used.  */
static size_t
cram_octet_string (ksba_parser_t tlv, int testmode)
{
  gpg_error_t err;
  size_t totallen;    /* Length of the non-crammed octet strings.  */
  size_t crammedlen;  /* Length of the crammed octet strings.  */
  const unsigned char *s, *save_s;
  unsigned char *d;
  size_t n, save_n;
  struct tag_info ti;

  if (tlv->ti.class == CLASS_UNIVERSAL && tlv->ti.tag == TYPE_OCTET_STRING)
    ;  /* Okay.  */
  else if (tlv->ti.class == CLASS_CONTEXT && tlv->ti.tag == 0)
    ;  /* Workaround for Mozilla bug; see T5793  */
  else
    return 0;  /* Oops - we should not have been called.  */
  if (!tlv->ti.is_constructed)
    return 0;  /* Oops - Not a constructed octet string.  */
  if (!tlv->ti.ndef && tlv->ti.length < 4)
    return 0;  /* Fixed length but too short.  */

  /* Let S point to the first octet string chunk.  */
  s = tlv->buffer;
  n = tlv->ti.ndef? tlv->bufsize : tlv->ti.length;

  d = (unsigned char *)s;
  totallen = crammedlen = 0;
  while (n)
    {
      save_s = s;
      save_n = n;
      if ((err=parse_tag (&s, &n, &ti, tlv->verbosity)))
        {
          if (tlv->verbosity > 1)
            {
              gpgrt_log_debug ("%s: parse_tag(n=%zu) failed : %s\n",
                                __func__, save_n, gpg_strerror (err));
              gpgrt_log_printhex (save_s, save_n > 40? 40:save_n,
                                  "%s: data was", __func__);
            }
          return 0;
        }
      if (tlv->verbosity > 1)
        gpgrt_log_debug ("%s:%s ti.ndef=%d ti.tag=%lu ti.length=%zu"
                         " (n %zu->%zu)\n",
                         __func__, testmode?"test:":"",
                         ti.ndef, ti.tag, ti.length, save_n, n);
      if (ti.class == CLASS_UNIVERSAL && ti.tag == TYPE_OCTET_STRING
          && !ti.ndef && !ti.is_constructed)
        {
          if (!testmode)
            memmove (d, s, ti.length);
          d += ti.length;  /* Update destination */
          totallen += ti.length + ti.nhdr;
          crammedlen += ti.length;
          s += ti.length;  /* Skip to next tag.  */
          n -= ti.length;
        }
      else if (ti.class == CLASS_UNIVERSAL && !ti.tag && !ti.is_constructed)
        {
          totallen += ti.nhdr;
          break; /* EOC - Ready */
        }
      else
        return 0; /* Invalid data.  */
    }
  if (!testmode)
    {
      memset (d, '\xfe', totallen - crammedlen);
      tlv->ti.length = totallen;
      tlv->ti.is_constructed = 0;
      tlv->ti.ndef = 0;
      tlv->crammed = crammedlen;
      if (tlv->verbosity > 1)
        {
          gpgrt_log_debug ("%s: crammed length is %zu\n", __func__, crammedlen);
          gpgrt_log_debug ("%s:   total length is %zu\n", __func__, totallen);
        }
      if (tlv->verbosity > 1)
        dump_to_file (tlv->buffer, totallen, "crammed");
    }
  return totallen;
}
