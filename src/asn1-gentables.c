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

#include "util.h"

#include "ksba.h"
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

static int
create_static_structure (AsnNode pointer, const char *file_name)
{
  FILE *file;
  AsnNode p;
  char *structure_name, *file_out_name;
  const char *char_p, *slash_p, *dot_p;

  char_p = file_name;
  slash_p = file_name;
  while ((char_p = strchr (char_p, '/')))
    {
      char_p++;
      slash_p = char_p;
    }

  char_p = slash_p;
  dot_p = file_name + strlen (file_name);

  while ((char_p = strchr (char_p, '.')))
    {
      dot_p = char_p;
      char_p++;
    }

  structure_name = xmalloc ( dot_p - slash_p + 100 );
  memcpy (structure_name, slash_p, dot_p - slash_p);
  structure_name[dot_p - slash_p] = 0;
  strcat (structure_name, "_asn1_tab");

  file_out_name = xmalloc (dot_p - file_name + 100);
  memcpy (file_out_name, file_name, dot_p - file_name);
  file_out_name[dot_p - file_name] = 0;
  strcat (file_out_name, "_asn1_tab.c");
  file = fopen (file_out_name, "w");
  if (!file)
    {
      print_error ("error creating `%s': %s\n",
                   file_out_name, strerror (errno));
      xfree (structure_name);
      xfree (file_out_name);
      return ASN_FILE_NOT_FOUND;
    }

  fprintf (file, "\n#include \"asn1-func.h\"\n\n");
  fprintf (file, "const static_asn %s[]={\n", structure_name);

  for (p = pointer; p; p = _ksba_asn_walk_tree (pointer, p))
    {
      /* set the help flags */
      p->flags.help_down  = !!p->down;
      p->flags.help_right = !!p->right;

      /* write a structure line */
      fputs ("  {", file);
      if (p->name)
	fprintf (file, "\"%s\",", p->name);
      else
	fprintf (file, "0");
      fprintf (file, ",%u", p->type);

      fputs (", {", file);
      fprintf (file, "%u", p->flags.class);
      fputs (p->flags.explicit       ? ",1":",0", file);
      fputs (p->flags.implicit       ? ",1":",0", file);
      fputs (p->flags.has_imports    ? ",1":",0", file);
      fputs (p->flags.assignment     ? ",1":",0", file);
      fputs (p->flags.one_param      ? ",1":",0", file);
      fputs (p->flags.has_tag        ? ",1":",0", file);
      fputs (p->flags.has_size       ? ",1":",0", file);
      fputs (p->flags.has_list       ? ",1":",0", file);
      fputs (p->flags.has_min_max    ? ",1":",0", file);
      fputs (p->flags.has_defined_by ? ",1":",0", file);
      fputs (p->flags.is_false       ? ",1":",0", file);
      fputs (p->flags.is_true        ? ",1":",0", file);
      fputs (p->flags.is_default     ? ",1":",0", file);
      fputs (p->flags.is_optional    ? ",1":",0", file);
      fputs (p->flags.is_utc_time    ? ",1":",0", file);
      fputs (p->flags.is_set         ? ",1":",0", file);
      fputs (p->flags.is_not_used    ? ",1":",0", file);
      fputs (p->flags.help_down      ? ",1":",0", file);
      fputs (p->flags.help_right     ? ",1":",0", file);
      fputs ("}", file);

      if (p->value)
	fprintf (file, ",\"%s\"", p->value);
      else
	fprintf (file, ",0");
      fputs ("},\n", file);
    }

  fprintf (file, "  {0,0}\n};\n");

  fclose (file);

  xfree (structure_name);
  xfree (file_out_name);
  return ASN_OK;
}



static void
one_file (FILE *fp, const char *fname)
{
  KsbaAsnTree tree;
  int rc;
  
  
  rc = ksba_asn_parse_file (fname, &tree);
  if (rc==ASN_SYNTAX_ERROR)
      print_error ("error parsing `%s': syntax error\n", fname);
  else if (rc==ASN_IDENTIFIER_NOT_FOUND)
      print_error ("error parsing `%s': identifier not found\n", fname);
  else if (rc==ASN_FILE_NOT_FOUND)
      print_error ("error parsing `%s': file not found\n", fname);
  else if (rc)
      print_error ("error parsing `%s': unknown error %d\n", fname, rc);
  else 
    {
      asn1_visit_tree (tree->parse_tree, NULL);
      create_static_structure (tree->parse_tree, fname);
    }
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
