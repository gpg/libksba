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

/* option --dump */
static int dump_only;
/* option --check */
static int check_only;

struct name_list_s {
  struct name_list_s *next;
  char name[1];
};


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

static struct name_list_s *
create_static_structure (AsnNode pointer, const char *file_name)
{
  AsnNode p;
  struct name_list_s *structure_name;
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

  structure_name = xmalloc (sizeof *structure_name + dot_p - slash_p + 100);
  structure_name->next = NULL;
  memcpy (structure_name->name, slash_p, dot_p - slash_p);
  structure_name->name[dot_p - slash_p] = 0;

  printf ("static const static_asn %s_asn1_tab[] = {\n",
          structure_name->name);

  for (p = pointer; p; p = _ksba_asn_walk_tree (pointer, p))
    {
      /* set the help flags */
      p->flags.help_down  = !!p->down;
      p->flags.help_right = !!p->right;

      /* write a structure line */
      fputs ("  {", stdout);
      if (p->name)
	fprintf (stdout, "\"%s\"", p->name);
      else
	fprintf (stdout, "NULL");
      fprintf (stdout, ",%u", p->type);

      fputs (", {", stdout);
      fprintf (stdout, "%u", p->flags.class);
      fputs (p->flags.explicit       ? ",1":",0", stdout);
      fputs (p->flags.implicit       ? ",1":",0", stdout);
      fputs (p->flags.has_imports    ? ",1":",0", stdout);
      fputs (p->flags.assignment     ? ",1":",0", stdout);
      fputs (p->flags.one_param      ? ",1":",0", stdout);
      fputs (p->flags.has_tag        ? ",1":",0", stdout);
      fputs (p->flags.has_size       ? ",1":",0", stdout);
      fputs (p->flags.has_list       ? ",1":",0", stdout);
      fputs (p->flags.has_min_max    ? ",1":",0", stdout);
      fputs (p->flags.has_defined_by ? ",1":",0", stdout);
      fputs (p->flags.is_false       ? ",1":",0", stdout);
      fputs (p->flags.is_true        ? ",1":",0", stdout);
      fputs (p->flags.has_default     ? ",1":",0", stdout);
      fputs (p->flags.is_optional    ? ",1":",0", stdout);
      fputs (p->flags.is_implicit    ? ",1":",0", stdout);
      fputs (p->flags.in_set         ? ",1":",0", stdout);
      fputs (p->flags.in_choice      ? ",1":",0", stdout);
      fputs (p->flags.in_array       ? ",1":",0", stdout);
      fputs (p->flags.is_any         ? ",1":",0", stdout);
      fputs (p->flags.not_used       ? ",1":",0", stdout);
      fputs (p->flags.help_down      ? ",1":",0", stdout);
      fputs (p->flags.help_right     ? ",1":",0", stdout);
      fputs ("}", stdout);

      if (p->valuetype == VALTYPE_CSTR)
	fprintf (stdout, ",\"%s\"", p->value.v_cstr);
      else if (p->valuetype == VALTYPE_LONG
               && p->type == TYPE_INTEGER && p->flags.assignment)
        fprintf (stdout, ",\"%ld\"", p->value.v_long);
      else if (p->valuetype == VALTYPE_ULONG)
        fprintf (stdout, ",\"%lu\"", p->value.v_ulong);
      else
        {
          if (p->valuetype)
            print_error ("can't store a value of type %d\n", p->valuetype);
          fprintf (stdout, ",0");
        }
      fputs ("},\n", stdout);
    }

  fprintf (stdout, "  {0,0}\n};\n");

  return structure_name;
}



static struct name_list_s *
one_file (FILE *fp, const char *fname, int *count)
{
  KsbaAsnTree tree;
  int rc;
    
  rc = ksba_asn_parse_file (fname, &tree, check_only);
  if (rc==KSBA_Syntax_Error)
      print_error ("error parsing `%s': syntax error\n", fname);
  else if (rc==KSBA_Identifier_Not_Found)
      print_error ("error parsing `%s': identifier not found\n", fname);
  else if (rc==KSBA_File_Error)
      print_error ("error parsing `%s': file not found\n", fname);
  else if (rc)
      print_error ("error parsing `%s': unknown error %d\n", fname, rc);
  else if (!check_only)
    {
      if (dump_only)
        ksba_asn_tree_dump (tree, dump_only==2? "<":NULL, stdout);
      else
        {
          if (!*count)
            printf ("\n"
                    "#include <config.h>\n"
                    "#include <stdio.h>\n"
                    "#include <string.h>\n"
                    "#include \"ksba.h\"\n"
                    "#include \"asn1-func.h\"\n"
                    "\n");
          ++*count;
          return create_static_structure (tree->parse_tree, fname);
        }
    }
  return 0;
}


int
main (int argc, char **argv)
{
  int count = 0;
  struct name_list_s *all_names = NULL, *nl;

  if (!argc || (argc > 1 &&
                (!strcmp (argv[1],"--help") || !strcmp (argv[1],"-h"))) )
    {
      fputs ("usage: asn1-gentables [--check] [--dump[-expanded]] [files.asn]\n",
             stderr);
      return 0;
    }
  
  argc--; argv++;
  if (argc && !strcmp (*argv,"--check"))
    {
      argc--; argv++;
      check_only = 1;
    }
  else if (argc && !strcmp (*argv,"--dump"))
    {
      argc--; argv++;
      dump_only = 1;
    }
  else if (argc && !strcmp (*argv,"--dump-expanded"))
    {
      argc--; argv++;
      dump_only = 2;
    }


  if (!argc)
    all_names = one_file (stdin, "-", &count);
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
              nl = one_file (fp, *argv, &count);
              fclose (fp);
              if (nl)
                {
                  nl->next = all_names;
                  all_names = nl;
                }
            }
        }
    }

  if (all_names && !error_counter)
    { /* Write the lookup function */
      printf ("\n\nconst static_asn *\n"
              "_ksba_asn_lookup_table (const char *name)\n"
              "{\n");
      for (nl=all_names; nl; nl = nl->next)
        printf ("  if (!strcmp (name, \"%s\"))\n"
                "    return %s_asn1_tab;\n", nl->name, nl->name);
      printf ("\n  return NULL;\n}\n");
    }

  return error_counter? 1:0;
}

