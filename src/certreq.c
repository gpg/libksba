/* certreq.c - create pkcs-10 messages
 *      Copyright (C) 2002 g10 Code GmbH
 *
 * This file is part of KSBA.
 *
 * KSBA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Fountion; either version 2 of the License, or
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
#include "util.h"

#include "cms.h"
#include "convert.h"
#include "keyinfo.h"
#include "der-encoder.h"
#include "ber-help.h"
#include "certreq.h"


/**
 * ksba_cms_new:
 * 
 * Create a new and empty CMS object
 * 
 * Return value: A CMS object or NULL in case of memory problems.
 **/
KsbaCertreq
ksba_certreq_new (void)
{
  KsbaCertreq cr;

  cr = xtrycalloc (1, sizeof *cr);
  if (!cr)
    return NULL;

  return cr;
}

/**
 * ksba_certreq_release:
 * @cms: A Certreq object
 * 
 * Release a Certreq object.
 **/
void
ksba_certreq_release (KsbaCertreq cr)
{
  if (!cr)
    return;
  xfree (cr->subject.der);
  xfree (cr->key.der);
  xfree (cr->cri.der);
  xfree (cr->sig_val.algo);
  xfree (cr->sig_val.value);
  xfree (cr);
}


KsbaError
ksba_certreq_set_writer (KsbaCertreq cr, KsbaWriter w)
{
  if (!cr || !w)
    return KSBA_Invalid_Value;
  cr->writer = w;
  return 0;
}


/* Provide a hash function so that we are able to hash the data */
void
ksba_certreq_set_hash_function (KsbaCertreq cr,
                                void (*hash_fnc)(void *, const void *, size_t),
                                void *hash_fnc_arg)
{
  if (cr)
    {
      cr->hash_fnc = hash_fnc;
      cr->hash_fnc_arg = hash_fnc_arg;
    }
}


/* Store the subject's name.  Does perform some syntactic checks on
   the name */
KsbaError
ksba_certreq_set_subject (KsbaCertreq cr, const char *name)
{
  
  if (!cr)
    return KSBA_Invalid_Value;
  xfree (cr->subject.der);
  cr->subject.der = NULL;
  return _ksba_dn_from_str (name, &cr->subject.der, &cr->subject.derlen);
}

/* Store the subject's name.  Does perform some syntactic checks on
   the name */
KsbaError
ksba_certreq_set_public_key (KsbaCertreq cr, KsbaConstSexp key)
{
  if (!cr)
    return KSBA_Invalid_Value;
  xfree (cr->key.der);
  cr->key.der = NULL;
  return _ksba_keyinfo_from_sexp (key, &cr->key.der, &cr->key.derlen);
}




/*
 * r_sig  = (sig-val
 *	      (<algo>
 *		(<param_name1> <mpi>)
 *		...
 *		(<param_namen> <mpi>)
 *	      ))
 * The sexp must be in canocial form. 
 * FIXME:  The code is mostly duplicated from cms.c
 * Note, that <algo> must be given as a stringified OID or the special
 * string "rsa" which is translated to sha1WithRSAEncryption
*/
KsbaError
ksba_certreq_set_sig_val (KsbaCertreq cr, KsbaConstSexp sigval)
{
  const char *s, *endp;
  unsigned long n;

  if (!cr)
    return KSBA_Invalid_Value;

  s = sigval;
  if (*s != '(')
    return KSBA_Invalid_Sexp;
  s++;

  n = strtoul (s, (char**)&endp, 10);
  s = endp;
  if (!n || *s!=':')
    return KSBA_Invalid_Sexp; /* we don't allow empty lengths */
  s++;
  if (n != 7 || memcmp (s, "sig-val", 7))
    return KSBA_Unknown_Sexp;
  s += 7;
  if (*s != '(')
    return digitp (s)? KSBA_Unknown_Sexp : KSBA_Invalid_Sexp;
  s++;

  /* break out the algorithm ID */
  n = strtoul (s, (char**)&endp, 10);
  s = endp;
  if (!n || *s != ':')
    return KSBA_Invalid_Sexp; /* we don't allow empty lengths */
  s++;
  xfree (cr->sig_val.algo);
  if (n==3 && s[0] == 'r' && s[1] == 's' && s[2] == 'a')
    { /* kludge to allow "rsa" to be passed as algorithm name */
      cr->sig_val.algo = xtrystrdup ("1.2.840.113549.1.1.5");
      if (!cr->sig_val.algo)
        return KSBA_Out_Of_Core;
    }
  else
    {
      cr->sig_val.algo = xtrymalloc (n+1);
      if (!cr->sig_val.algo)
        return KSBA_Out_Of_Core;
      memcpy (cr->sig_val.algo, s, n);
      cr->sig_val.algo[n] = 0;
    }
  s += n;

  /* And now the values - FIXME: For now we only support one */
  /* fixme: start loop */
  if (*s != '(')
    return digitp (s)? KSBA_Unknown_Sexp : KSBA_Invalid_Sexp;
  s++;
  n = strtoul (s, (char**)&endp, 10);
  s = endp;
  if (!n || *s != ':')
    return KSBA_Invalid_Sexp; 
  s++;
  s += n; /* ignore the name of the parameter */
  
  if (!digitp(s))
    return KSBA_Unknown_Sexp; /* but may also be an invalid one */
  n = strtoul (s, (char**)&endp, 10);
  s = endp;
  if (!n || *s != ':')
    return KSBA_Invalid_Sexp; 
  s++;
  xfree (cr->sig_val.value);
  cr->sig_val.value = xtrymalloc (n);
  if (!cr->sig_val.value)
    return KSBA_Out_Of_Core;
  memcpy (cr->sig_val.value, s, n);
  cr->sig_val.valuelen = n;
  s += n;
  if ( *s != ')')
    return KSBA_Unknown_Sexp; /* but may also be an invalid one */
  s++;
  /* fixme: end loop over parameters */

  /* we need 2 closing parenthesis */
  if ( *s != ')' || s[1] != ')')
    return KSBA_Invalid_Sexp; 

  return 0;
}



/* Build a value tree from the already stored values. */
static KsbaError
build_cri (KsbaCertreq cr)
{
  KsbaError err;
  KsbaWriter writer;
  void *value = NULL;
  size_t valuelen;

  if (!(writer = ksba_writer_new ()))
    err = KSBA_Out_Of_Core;
  else
    err = ksba_writer_set_mem (writer, 2048);
  if (err)
    goto leave;

  /* We write all stuff out to a temporary writer object, then use
     this object to create the cri and store the cri image */

  /* store version v1 (which is a 0) */
  err = _ksba_ber_write_tl (writer, TYPE_INTEGER, CLASS_UNIVERSAL, 0, 1);
  if (!err)
    err = ksba_writer_write (writer, "", 1);
  if (err)
    goto leave;

  /* store the subject */
  if (!cr->subject.der)
    {
      err = KSBA_Missing_Value;
      goto leave;
    }
  err = ksba_writer_write (writer, cr->subject.der, cr->subject.derlen);
  if (err)
    goto leave;

  /* store the public key info */
  if (!cr->key.der)
    {
      err = KSBA_Missing_Value;
      goto leave;
    }
  err = ksba_writer_write (writer, cr->key.der, cr->key.derlen);
  if (err)
    goto leave;
  
  /* FIXME: store the attributes */


  /* pack it into the sequence */
  value = ksba_writer_snatch_mem (writer, &valuelen);
  if (!value)
    {
      err = KSBA_Out_Of_Core;
      goto leave;
    }
  /* reinitialize the buffer to create the outer sequence */
  err = ksba_writer_set_mem (writer, valuelen+10);
  if (err)
    goto leave;
  /* write outer sequence */
  err = _ksba_ber_write_tl (writer, TYPE_SEQUENCE, CLASS_UNIVERSAL,
                            1, valuelen);
  if (!err)
    err = ksba_writer_write (writer, value, valuelen);
  if (err)
    goto leave;
  
  /* and store the final result */
  cr->cri.der = ksba_writer_snatch_mem (writer, &cr->cri.derlen);
  if (!cr->cri.der)
    err = KSBA_Out_Of_Core;

 leave:
  ksba_writer_release (writer);
  xfree (value);
  return err;
}

static KsbaError
hash_cri (KsbaCertreq cr)
{
  if (!cr->hash_fnc)
    return KSBA_Missing_Action;
  if (!cr->cri.der)
    return KSBA_Invalid_State;
  cr->hash_fnc (cr->hash_fnc_arg, cr->cri.der, cr->cri.derlen);
  return 0;
}


/* The user has calculated the signatures and we can now write
   the signature */
static KsbaError 
sign_and_write (KsbaCertreq cr) 
{
  KsbaError err;
  KsbaWriter writer;
  void *value = NULL;
  size_t valuelen;

  if (!(writer = ksba_writer_new ()))
    err = KSBA_Out_Of_Core;
  else
    err = ksba_writer_set_mem (writer, 2048);
  if (err)
    goto leave;

  /* store the cri */
  if (!cr->cri.der)
    {
      err = KSBA_Missing_Value;
      goto leave;
    }
  err = ksba_writer_write (writer, cr->cri.der, cr->cri.derlen);
  if (err) 
    goto leave;
  
  /* store the signatureAlgorithm */
  if (!cr->sig_val.algo)
    return KSBA_Missing_Value;
  err = _ksba_der_write_algorithm_identifier (writer, 
                                              cr->sig_val.algo, NULL, 0);
  if (err) 
    goto leave;

  /* write the signature */
  err = _ksba_ber_write_tl (writer, TYPE_BIT_STRING, CLASS_UNIVERSAL, 0,
                            1 + cr->sig_val.valuelen);
  if (!err)
    err = ksba_writer_write (writer, "", 1);
  if (!err)
    err = ksba_writer_write (writer, cr->sig_val.value, cr->sig_val.valuelen);
  if (err)
    goto leave;

  /* pack it into the outer sequence */
  value = ksba_writer_snatch_mem (writer, &valuelen);
  if (!value)
    {
      err = KSBA_Out_Of_Core;
      goto leave;
    }
  err = ksba_writer_set_mem (writer, valuelen+10);
  if (err)
    goto leave;
  /* write outer sequence */
  err = _ksba_ber_write_tl (writer, TYPE_SEQUENCE, CLASS_UNIVERSAL,
                            1, valuelen);
  if (!err)
    err = ksba_writer_write (writer, value, valuelen);
  if (err)
    goto leave;

  /* and finally write the result */
  xfree (value);
  value = ksba_writer_snatch_mem (writer, &valuelen);
  if (!value)
    err = KSBA_Out_Of_Core;
  else if (!cr->writer)
    err = KSBA_Missing_Action;
  else
    err = ksba_writer_write (cr->writer, value, valuelen);

 leave:
  ksba_writer_release (writer);
  xfree (value);
  return err;
}



/* The main function to build a certificate request.  It used used in
   a loop so allow for interaction between the function and the caller */
KsbaError
ksba_certreq_build (KsbaCertreq cr, KsbaStopReason *r_stopreason)
{
  enum { 
    sSTART,
    sHASHING,
    sGOTSIG,
    sERROR
  } state = sERROR;
  KsbaError err = 0;
  KsbaStopReason stop_reason;

  if (!cr || !r_stopreason)
    return KSBA_Invalid_Value;

  if (!cr->any_build_done)
    { /* first time initialization of the stop reason */
      *r_stopreason = 0;
      cr->any_build_done = 1;
    }

  /* Calculate state from last reason */
  stop_reason = *r_stopreason;
  *r_stopreason = KSBA_SR_RUNNING;
  switch (stop_reason)
    {
    case 0:
      state = sSTART;
      break;
    case KSBA_SR_NEED_HASH:
      state = sHASHING;
      break;
    case KSBA_SR_NEED_SIG:
      if (!cr->sig_val.algo)
        err = KSBA_Missing_Action; 
      else
        state = sGOTSIG;
      break;
    case KSBA_SR_RUNNING:
      err = KSBA_Invalid_State;
      break;
    default:
      err = KSBA_Bug;
      break;
    }
  if (err)
    return err;

  /* Do the action */
  switch (state)
    {
    case sSTART:
      err = build_cri (cr);
      break;
    case sHASHING:
      err = hash_cri (cr);
      break;
    case sGOTSIG:
      err = sign_and_write (cr);
      break;
    default:
      err = KSBA_Invalid_State;
      break;
    }
  if (err)
    return err;

  /* Calculate new stop reason */
  switch (state)
    {
    case sSTART:
      stop_reason = KSBA_SR_NEED_HASH; /* caller should set the hash function*/
      break;
    case sHASHING:
      stop_reason = KSBA_SR_NEED_SIG;
      break;
    case sGOTSIG:
      stop_reason = KSBA_SR_READY;
      break;
    default:
      break;
    }
    
  *r_stopreason = stop_reason;
  return 0;
}
