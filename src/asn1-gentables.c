/* asn1-gentables.c - Tool to create required ASN tables
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
#include <errno.h>
#include <stdarg.h>

#include "asn1-parse.h"
#include "asn1-func.h"

#define PGMNAME "asn1-gentables"

#if (__GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 5 ))
# define  ATTR_PRINTF(a,b)  __attribute__ ((format (printf,a,b)))
#else
# define  ATTR_PRINTF(a,b) 
#endif

/* keep track of parsing error */
static int error_counter;


static void print_error (const char *fmt, ... )  ATTR_PRINTF(1,2);



static void
print_error (const char *fmt, ... )  
{
  va_list arg_ptr ;

  va_start (arg_ptr, fmt);
  fputs (PGMNAME ": ", stderr);
  vfprintf (stderr, fmt, arg_ptr);
  va_end (arg_ptr);
  error_counter++;
  
}


static void
one_file (FILE *fp, const char *fname)
{
  int rc;
  
  rc = asn1_parser_asn1_file_c (fname);
  if (rc==ASN_SYNTAX_ERROR)
      print_error ("error parsing `%s': syntax error\n", fname);
  else if (rc==ASN_IDENTIFIER_NOT_FOUND)
      print_error ("error parsing `%s': identifier not found\n", fname);
  else if (rc==ASN_FILE_NOT_FOUND)
      print_error ("error parsing `%s': file not found\n", fname);
  else if (rc)
      print_error ("error parsing `%s': unknown error %d\n", fname, rc);
  
}


int
main (int argc, char **argv)
{
  if (!argc || (argc > 1 &&
                (!strcmp (argv[1],"--help") || !strcmp (argv[1],"-h"))) )
    {
      fputs ("usage: asn1-gentables [files.asn]\n", stderr);
      return 0;
    }
  
  argc--; argv++;
  
  if (!argc)
    one_file (stdin, "-");
  else
    {
      for (; argc; argc--, argv++) 
        {
          FILE *fp;
          
          fp = fopen (*argv, "r");
          if (!fp)
              print_error ("can't open `%s': %s\n", *argv, strerror (errno));
          else
            {
              one_file (fp, *argv);
              fclose (fp);
            }
        }
    }
  return error_counter? 1:0;
}
