/* time.c - UTCTime and GeneralizedTime helper
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
#include <time.h>
#include <assert.h>

#include "util.h"
#include "convert.h"


/* Converts an UTCTime or GeneralizedTime to epoc.  Returns (time_t)-1
   on error. The function figures automagically the right format.
   fixme: Currently we only zupport Zulu time and no timezone */
time_t 
_ksba_asntime_to_epoch (const char *buffer, size_t length)
{ 
  const char *s;
  size_t n;
  struct tm buf;
  int year;

  for (s=buffer, n=0; n < length && digitp (s); n++, s++)
    ;
  if ((n != 12 && n != 14) || *s != 'Z')
    return (time_t)(-1);
  
  s = buffer;
  if (n==12)
    {
      year = atoi_2 (s);
      s += 2;
      year += year < 50? 2000:1900;
    }
  else
    {
      year = atoi_4 (s);
      s += 4;
    }
  if (year < 1900)
    return (time_t)(-1);
  buf.tm_year = year - 1900;
  buf.tm_mon = atoi_2 (s) - 1; 
  s += 2;
  buf.tm_mday = atoi_2 (s);
  s += 2;
  buf.tm_hour = atoi_2 (s);
  s += 2;
  buf.tm_min = atoi_2 (s);
  s += 2;
  buf.tm_sec = atoi_2 (s);
  s += 2;
  buf.tm_isdst = 0;

#ifdef HAVE_TIMEGM
  return timegm (&buf);
#else
  {
#warning We should reset TZ if we cannot use timegm()
    time_t tim;

    putenv ("TZ=UTC");
    tim = mktime (&buf);
    return tim;
  }
#endif
}


/* convert an epoch time T into Generalized Time and return that in 
   rbuf and rlength.  Caller must free the returned buffer */
int
_ksba_asntime_from_epoch (time_t t, char **rbuf, size_t *rlength)
{
  *rbuf = NULL;
  *rlength = 0;



  return -1; /* error */
}






