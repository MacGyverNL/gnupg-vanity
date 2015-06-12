/* genkey.c - Generate a keypair
 * Copyright (C) 2002, 2003, 2004, 2007, 2010 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "agent.h"
#include "i18n.h"
#include "exechelp.h"
#include "sysutils.h"

// EDITED FOR VANITY
#include "common/openpgpdefs.h"
#define MAX_FINGERPRINT_LEN 20
typedef struct kbnode_struct *KBNODE;
typedef struct kbnode_struct *kbnode_t;
#include "g10/packet.h"
#include "g10/keydb.h"

// Copied a bunch of functions required for fingerprint calculation.

// from g10/keygen.c:
static gpg_error_t
ecckey_from_sexp (gcry_mpi_t *array, gcry_sexp_t sexp, int algo)
{
  gpg_error_t err;
  gcry_sexp_t list, l2;
  char *curve;
  int i;
  const char *oidstr;
  unsigned int nbits;

  array[0] = NULL;
  array[1] = NULL;
  array[2] = NULL;

  list = gcry_sexp_find_token (sexp, "public-key", 0);
  if (!list)
    return gpg_error (GPG_ERR_INV_OBJ);
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  if (!list)
    return gpg_error (GPG_ERR_NO_OBJ);

  l2 = gcry_sexp_find_token (list, "curve", 0);
  if (!l2)
    {
      err = gpg_error (GPG_ERR_NO_OBJ);
      goto leave;
    }
  curve = gcry_sexp_nth_string (l2, 1);
  if (!curve)
    {
      err = gpg_error (GPG_ERR_NO_OBJ);
      goto leave;
    }
  gcry_sexp_release (l2);
  oidstr = openpgp_curve_to_oid (curve, &nbits);
  if (!oidstr)
    {
      /* That can't happen because we used one of the curves
         gpg_curve_to_oid knows about.  */
      err = gpg_error (GPG_ERR_INV_OBJ);
      goto leave;
    }
  err = openpgp_oid_from_str (oidstr, &array[0]);
  if (err)
    goto leave;

  l2 = gcry_sexp_find_token (list, "q", 0);
  if (!l2)
    {
      err = gpg_error (GPG_ERR_NO_OBJ);
      goto leave;
    }
  array[1] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (l2);
  if (!array[1])
    {
      err = gpg_error (GPG_ERR_INV_OBJ);
      goto leave;
    }
  gcry_sexp_release (list);

  if (algo == PUBKEY_ALGO_ECDH)
    {
      // Removed this body, shouldn't be hit anyway.
      log_debug("ONLY USE THIS WITH EDDSA!\n");
      BUG();
    }

 leave:
  if (err)
    {
      for (i=0; i < 3; i++)
        {
          gcry_mpi_release (array[i]);
          array[i] = NULL;
        }
    }
  return err;
}

// from common/host2net.h:
static inline u32
buf32_to_u32 (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((u32)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

// from g10/keyid.c:
/* Hash a public key.  This function is useful for v4 fingerprints and
   for v3 or v4 key signing. */
void
hash_public_key (gcry_md_hd_t md, PKT_public_key *pk)
{
  unsigned int n = 6;
  unsigned int nn[PUBKEY_MAX_NPKEY];
  byte *pp[PUBKEY_MAX_NPKEY];
  int i;
  unsigned int nbits;
  size_t nbytes;
  int npkey = 2; // VANITY: Hardcoded pubkey_algo to EDDSA from
                 // pubkey_get_npkey in g10/misc.c

  /* FIXME: We can avoid the extra malloc by calling only the first
     mpi_print here which computes the required length and calling the
     real mpi_print only at the end.  The speed advantage would only be
     for ECC (opaque MPIs) or if we could implement an mpi_print
     variant with a callback handler to do the hashing.  */
  if (npkey==0 && pk->pkey[0]
      && gcry_mpi_get_flag (pk->pkey[0], GCRYMPI_FLAG_OPAQUE))
    {
      pp[0] = gcry_mpi_get_opaque (pk->pkey[0], &nbits);
      nn[0] = (nbits+7)/8;
      n+=nn[0];
    }
  else
    {
      for (i=0; i < npkey; i++ )
        {
          if (!pk->pkey[i])
            {
              /* This case may only happen if the parsing of the MPI
                 failed but the key was anyway created.  May happen
                 during "gpg KEYFILE".  */
              pp[i] = NULL;
              nn[i] = 0;
            }
          else if (gcry_mpi_get_flag (pk->pkey[i], GCRYMPI_FLAG_OPAQUE))
            {
              const void *p;

              p = gcry_mpi_get_opaque (pk->pkey[i], &nbits);
              pp[i] = xmalloc ((nbits+7)/8);
              if (p)
                memcpy (pp[i], p, (nbits+7)/8);
              else
                pp[i] = NULL;
              nn[i] = (nbits+7)/8;
              n += nn[i];
            }
          else
            {
              if (gcry_mpi_print (GCRYMPI_FMT_PGP, NULL, 0,
                                  &nbytes, pk->pkey[i]))
                BUG ();
              pp[i] = xmalloc (nbytes);
              if (gcry_mpi_print (GCRYMPI_FMT_PGP, pp[i], nbytes,
                                  &nbytes, pk->pkey[i]))
                BUG ();
              nn[i] = nbytes;
              n += nn[i];
            }
        }
    }

  gcry_md_putc ( md, 0x99 );     /* ctb */
  /* What does it mean if n is greater than than 0xFFFF ? */
  gcry_md_putc ( md, n >> 8 );   /* 2 byte length header */
  gcry_md_putc ( md, n );
  gcry_md_putc ( md, pk->version );

  gcry_md_putc ( md, pk->timestamp >> 24 );
  gcry_md_putc ( md, pk->timestamp >> 16 );
  gcry_md_putc ( md, pk->timestamp >>  8 );
  gcry_md_putc ( md, pk->timestamp       );

  gcry_md_putc ( md, pk->pubkey_algo );

  if(npkey==0 && pk->pkey[0]
     && gcry_mpi_get_flag (pk->pkey[0], GCRYMPI_FLAG_OPAQUE))
    {
      if (pp[0])
        gcry_md_write (md, pp[0], nn[0]);
    }
  else
    {
      for(i=0; i < npkey; i++ )
        {
          if (pp[i])
            gcry_md_write ( md, pp[i], nn[i] );
          xfree(pp[i]);
        }
    }
}

// from g10/keyid.c:
static gcry_md_hd_t
do_fingerprint_md( PKT_public_key *pk )
{
  gcry_md_hd_t md;

  if (gcry_md_open (&md, DIGEST_ALGO_SHA1, 0))
    BUG ();
  hash_public_key(md,pk);
  gcry_md_final( md );

  return md;
}


// from g10/keyid.c:
/*
 * Get the keyid from the public key and put it into keyid
 * if this is not NULL. Return the 32 low bits of the keyid.
 */
u32
keyid_from_pk (PKT_public_key *pk, u32 *keyid)
{
  u32 lowbits;
  u32 dummy_keyid[2];

  if (!keyid)
    keyid = dummy_keyid;

  if( pk->keyid[0] || pk->keyid[1] )
    {
      keyid[0] = pk->keyid[0];
      keyid[1] = pk->keyid[1];
      lowbits = keyid[1];
    }
  else
    {
      const byte *dp;
      gcry_md_hd_t md;

      md = do_fingerprint_md(pk);
      if(md)
        {
          dp = gcry_md_read ( md, 0 );
          keyid[0] = buf32_to_u32 (dp+12);
          keyid[1] = buf32_to_u32 (dp+16);
          lowbits = keyid[1];
          gcry_md_close (md);
          pk->keyid[0] = keyid[0];
          pk->keyid[1] = keyid[1];
        }
      else
        pk->keyid[0]=pk->keyid[1]=keyid[0]=keyid[1]=lowbits=0xFFFFFFFF;
    }

  return lowbits;
}



// from g10/keyid.c:
/*
 * Return a byte array with the fingerprint for the given PK/SK
 * The length of the array is returned in ret_len. Caller must free
 * the array or provide an array of length MAX_FINGERPRINT_LEN.
 */
byte *
fingerprint_from_pk (PKT_public_key *pk, byte *array, size_t *ret_len)
{
  const byte *dp;
  size_t len;
  gcry_md_hd_t md;

  md = do_fingerprint_md(pk);
  dp = gcry_md_read( md, 0 );
  len = gcry_md_get_algo_dlen (gcry_md_get_algo (md));
  assert( len <= MAX_FINGERPRINT_LEN );
  if (!array)
    array = xmalloc ( len );
  memcpy (array, dp, len );
  pk->keyid[0] = buf32_to_u32 (dp+12);
  pk->keyid[1] = buf32_to_u32 (dp+16);
  gcry_md_close( md);

  if (ret_len)
    *ret_len = len;
  return array;
}


// from g10/keyid.c:
/* Return an allocated buffer with the fingerprint of PK formatted as
   a plain hexstring.  */
char *
hexfingerprint (PKT_public_key *pk)
{
  unsigned char fpr[MAX_FINGERPRINT_LEN];
  size_t len;
  char *result;

  fingerprint_from_pk (pk, fpr, &len);
  result = xmalloc (2 * len + 1);
  bin2hex (fpr, len, result);
  return result;
}
// VANITY EDITS END

static int
store_key (gcry_sexp_t private, const char *passphrase, int force,
	unsigned long s2k_count)
{
  int rc;
  unsigned char *buf;
  size_t len;
  unsigned char grip[20];

  if ( !gcry_pk_get_keygrip (private, grip) )
    {
      log_error ("can't calculate keygrip\n");
      return gpg_error (GPG_ERR_GENERAL);
    }

  len = gcry_sexp_sprint (private, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = gcry_malloc_secure (len);
  if (!buf)
      return out_of_core ();
  len = gcry_sexp_sprint (private, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);

  if (passphrase)
    {
      unsigned char *p;

      rc = agent_protect (buf, passphrase, &p, &len, s2k_count);
      if (rc)
        {
          xfree (buf);
          return rc;
        }
      xfree (buf);
      buf = p;
    }

  rc = agent_write_private_key (grip, buf, len, force);
  xfree (buf);
  return rc;
}


/* Count the number of non-alpha characters in S.  Control characters
   and non-ascii characters are not considered.  */
static size_t
nonalpha_count (const char *s)
{
  size_t n;

  for (n=0; *s; s++)
    if (isascii (*s) && ( isdigit (*s) || ispunct (*s) ))
      n++;

  return n;
}


/* Check PW against a list of pattern.  Return 0 if PW does not match
   these pattern.  */
static int
check_passphrase_pattern (ctrl_t ctrl, const char *pw)
{
  gpg_error_t err = 0;
  const char *pgmname = gnupg_module_name (GNUPG_MODULE_NAME_CHECK_PATTERN);
  FILE *infp;
  const char *argv[10];
  pid_t pid;
  int result, i;

  (void)ctrl;

  infp = gnupg_tmpfile ();
  if (!infp)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error creating temporary file: %s\n"), gpg_strerror (err));
      return 1; /* Error - assume password should not be used.  */
    }

  if (fwrite (pw, strlen (pw), 1, infp) != 1)
    {
      err = gpg_error_from_syserror ();
      log_error (_("error writing to temporary file: %s\n"),
                 gpg_strerror (err));
      fclose (infp);
      return 1; /* Error - assume password should not be used.  */
    }
  fseek (infp, 0, SEEK_SET);
  clearerr (infp);

  i = 0;
  argv[i++] = "--null";
  argv[i++] = "--",
  argv[i++] = opt.check_passphrase_pattern,
  argv[i] = NULL;
  assert (i < sizeof argv);

  if (gnupg_spawn_process_fd (pgmname, argv, fileno (infp), -1, -1, &pid))
    result = 1; /* Execute error - assume password should no be used.  */
  else if (gnupg_wait_process (pgmname, pid, 1, NULL))
    result = 1; /* Helper returned an error - probably a match.  */
  else
    result = 0; /* Success; i.e. no match.  */
  gnupg_release_process (pid);

  /* Overwrite our temporary file. */
  fseek (infp, 0, SEEK_SET);
  clearerr (infp);
  for (i=((strlen (pw)+99)/100)*100; i > 0; i--)
    putc ('\xff', infp);
  fflush (infp);
  fclose (infp);
  return result;
}


static int
take_this_one_anyway2 (ctrl_t ctrl, const char *desc, const char *anyway_btn)
{
  gpg_error_t err;

  if (opt.enforce_passphrase_constraints)
    {
      err = agent_show_message (ctrl, desc, _("Enter new passphrase"));
      if (!err)
        err = gpg_error (GPG_ERR_CANCELED);
    }
  else
    err = agent_get_confirmation (ctrl, desc,
                                  anyway_btn, _("Enter new passphrase"), 0);
  return err;
}


static int
take_this_one_anyway (ctrl_t ctrl, const char *desc)
{
  return take_this_one_anyway2 (ctrl, desc, _("Take this one anyway"));
}


/* Check whether the passphrase PW is suitable. Returns 0 if the
   passphrase is suitable and true if it is not and the user should be
   asked to provide a different one.  If SILENT is set, no message are
   displayed.  */
int
check_passphrase_constraints (ctrl_t ctrl, const char *pw, int silent)
{
  gpg_error_t err = 0;
  unsigned int minlen = opt.min_passphrase_len;
  unsigned int minnonalpha = opt.min_passphrase_nonalpha;
  char *msg1 = NULL;
  char *msg2 = NULL;
  char *msg3 = NULL;

  if (!pw)
    pw = "";

  /* The first check is to warn about an empty passphrase. */
  if (!*pw)
    {
      const char *desc = (opt.enforce_passphrase_constraints?
                          _("You have not entered a passphrase!%0A"
                            "An empty passphrase is not allowed.") :
                          _("You have not entered a passphrase - "
                            "this is in general a bad idea!%0A"
                            "Please confirm that you do not want to "
                            "have any protection on your key."));

      if (silent)
        return gpg_error (GPG_ERR_INV_PASSPHRASE);

      err = take_this_one_anyway2 (ctrl, desc,
                                   _("Yes, protection is not needed"));
      goto leave;
    }

  /* Now check the constraints and collect the error messages unless
     in in silent mode which returns immediately.  */
  if (utf8_charcount (pw) < minlen )
    {
      if (silent)
        {
          err = gpg_error (GPG_ERR_INV_PASSPHRASE);
          goto leave;
        }

      msg1 = xtryasprintf
        ( ngettext ("A passphrase should be at least %u character long.",
                    "A passphrase should be at least %u characters long.",
                    minlen), minlen );
      if (!msg1)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  if (nonalpha_count (pw) < minnonalpha )
    {
      if (silent)
        {
          err = gpg_error (GPG_ERR_INV_PASSPHRASE);
          goto leave;
        }

      msg2 = xtryasprintf
        ( ngettext ("A passphrase should contain at least %u digit or%%0A"
                    "special character.",
                    "A passphrase should contain at least %u digits or%%0A"
                    "special characters.",
                    minnonalpha), minnonalpha );
      if (!msg2)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  /* If configured check the passphrase against a list of known words
     and pattern.  The actual test is done by an external program.
     The warning message is generic to give the user no hint on how to
     circumvent this list.  */
  if (*pw && opt.check_passphrase_pattern &&
      check_passphrase_pattern (ctrl, pw))
    {
      if (silent)
        {
          err = gpg_error (GPG_ERR_INV_PASSPHRASE);
          goto leave;
        }

      msg3 = xtryasprintf
        (_("A passphrase may not be a known term or match%%0A"
           "certain pattern."));
      if (!msg3)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  if (msg1 || msg2 || msg3)
    {
      char *msg;
      size_t n;

      msg = strconcat
        (_("Warning: You have entered an insecure passphrase."),
         "%0A%0A",
         msg1? msg1 : "", msg1? "%0A" : "",
         msg2? msg2 : "", msg2? "%0A" : "",
         msg3? msg3 : "", msg3? "%0A" : "",
         NULL);
      if (!msg)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
      /* Strip a trailing "%0A".  */
      n = strlen (msg);
      if (n > 3 && !strcmp (msg + n - 3, "%0A"))
        msg[n-3] = 0;

      /* Show error messages.  */
      err = take_this_one_anyway (ctrl, msg);
      xfree (msg);
    }

 leave:
  xfree (msg1);
  xfree (msg2);
  xfree (msg3);
  return err;
}


/* Callback function to compare the first entered PIN with the one
   currently being entered. */
static int
reenter_compare_cb (struct pin_entry_info_s *pi)
{
  const char *pin1 = pi->check_cb_arg;

  if (!strcmp (pin1, pi->pin))
    return 0; /* okay */
  return -1;
}


/* Ask the user for a new passphrase using PROMPT.  On success the
   function returns 0 and store the passphrase at R_PASSPHRASE; if the
   user opted not to use a passphrase NULL will be stored there.  The
   user needs to free the returned string.  In case of an error and
   error code is returned and NULL stored at R_PASSPHRASE.  */
gpg_error_t
agent_ask_new_passphrase (ctrl_t ctrl, const char *prompt,
                          char **r_passphrase)
{
  gpg_error_t err;
  const char *text1 = prompt;
  const char *text2 = _("Please re-enter this passphrase");
  const char *initial_errtext = NULL;
  struct pin_entry_info_s *pi, *pi2;

  *r_passphrase = NULL;

  if (ctrl->pinentry_mode == PINENTRY_MODE_LOOPBACK)
    {
	size_t size;
	size_t len = 100;
	unsigned char *buffer;

	err = pinentry_loopback(ctrl, "NEW_PASSPHRASE", &buffer, &size, len);
	if (!err)
	  {
	    if (size)
	      {
		buffer[size] = 0;
		*r_passphrase = buffer;
	      }
	    else
	        *r_passphrase = NULL;
	  }
	return err;
    }

  pi = gcry_calloc_secure (2, sizeof (*pi) + 100);
  pi2 = pi + (sizeof *pi + 100);
  pi->max_length = 100;
  pi->max_tries = 3;
  pi->with_qualitybar = 1;
  pi->with_repeat = 1;
  pi2->max_length = 100;
  pi2->max_tries = 3;
  pi2->check_cb = reenter_compare_cb;
  pi2->check_cb_arg = pi->pin;

 next_try:
  err = agent_askpin (ctrl, text1, NULL, initial_errtext, pi, NULL, 0);
  initial_errtext = NULL;
  if (!err)
    {
      if (check_passphrase_constraints (ctrl, pi->pin, 0))
        {
          pi->failed_tries = 0;
          pi2->failed_tries = 0;
          goto next_try;
        }
      /* Unless the passphrase is empty or the pinentry told us that
         it already did the repetition check, ask to confirm it.  */
      if (*pi->pin && !pi->repeat_okay)
        {
          err = agent_askpin (ctrl, text2, NULL, NULL, pi2, NULL, 0);
          if (err == -1)
            { /* The re-entered one did not match and the user did not
                 hit cancel. */
              initial_errtext = _("does not match - try again");
              goto next_try;
            }
        }
    }

  if (!err && *pi->pin)
    {
      /* User wants a passphrase. */
      *r_passphrase = xtrystrdup (pi->pin);
      if (!*r_passphrase)
        err = gpg_error_from_syserror ();
    }
  xfree (pi);
  return err;
}



/* Generate a new keypair according to the parameters given in
   KEYPARAM.  If CACHE_NONCE is given first try to lookup a passphrase
   using the cache nonce.  If NO_PROTECTION is true the key will not
   be protected by a passphrase.  If OVERRIDE_PASSPHRASE is true that
   passphrase will be used for the new key.  */
int
agent_genkey (ctrl_t ctrl, const char *cache_nonce,
              const char *keyparam, size_t keyparamlen, int no_protection,
              const char *override_passphrase, int preset, membuf_t *outbuf)
{
  gcry_sexp_t s_keyparam, s_key, s_private, s_public;
  char *passphrase_buffer = NULL;
  const char *passphrase;
  int rc;
  size_t len;
  char *buf;
  // EDITED FOR VANITY
  int match = 0; // Loop guard, if match, break out.
  long long unsigned int iterations = 0; // Count iterations.
  int err;
  int algo = PUBKEY_ALGO_EDDSA;
  // Timestamp range for bruteforcing:
  u32 timestamp = make_timestamp ();
  u32 tmpstamp = timestamp;
  u32 lowertime = timestamp - 2000000;
  // keyid and fingerprint storage:
  u32 keyid;
  byte *fp;
  // dummy pubkey to determine current fingerprint:
  PKT_public_key *pk;
  pk = xtrycalloc (1, sizeof *pk);
  if (!pk)
    {
      err = gpg_error_from_syserror ();
      gcry_sexp_release (s_key);
      return err;
    }

  log_debug("Starting key generation\n");
  // Fill out the relevant values in the dummy pubkey.
  pk->timestamp = timestamp;
  pk->version = 4;
  pk->pubkey_algo = algo;

  // allocate storage for fingerprint calculations.
  fp = xmalloc (MAX_FINGERPRINT_LEN);
  // VANITY EDITS END

  rc = gcry_sexp_sscan (&s_keyparam, NULL, keyparam, keyparamlen);
  if (rc)
    {
      log_error ("failed to convert keyparam: %s\n", gpg_strerror (rc));
      return gpg_error (GPG_ERR_INV_DATA);
    }

  /* Get the passphrase now, cause key generation may take a while. */
  if (override_passphrase)
    passphrase = override_passphrase;
  else if (no_protection || !cache_nonce)
    passphrase = NULL;
  else
    {
      passphrase_buffer = agent_get_cache (cache_nonce, CACHE_MODE_NONCE);
      passphrase = passphrase_buffer;
    }

  if (passphrase || no_protection)
    ;
  else
    {
      rc = agent_ask_new_passphrase (ctrl,
                                     _("Please enter the passphrase to%0A"
                                       "protect your new key"),
                                     &passphrase_buffer);
      if (rc)
        return rc;
      passphrase = passphrase_buffer;
    }

  // EDITED FOR VANITY
  while (match == 0) {
    // start looping over generation.
    // VANITY EDITS END
  
    rc = gcry_pk_genkey (&s_key, s_keyparam );
    // EDITED FOR VANITY
    // Do not release the keyparam, we need it again in the loop.
    //gcry_sexp_release (s_keyparam);
    // VANITY EDITS END
    if (rc)
      {
        log_error ("key generation failed: %s\n", gpg_strerror (rc));
        xfree (passphrase_buffer);
        return rc;
      }
  
    /* break out the parts */
    s_private = gcry_sexp_find_token (s_key, "private-key", 0);
    if (!s_private)
      {
        log_error ("key generation failed: invalid return value\n");
        gcry_sexp_release (s_key);
        xfree (passphrase_buffer);
        return gpg_error (GPG_ERR_INV_DATA);
      }
    s_public = gcry_sexp_find_token (s_key, "public-key", 0);
    if (!s_public)
      {
        log_error ("key generation failed: invalid return value\n");
        gcry_sexp_release (s_private);
        gcry_sexp_release (s_key);
        xfree (passphrase_buffer);
        return gpg_error (GPG_ERR_INV_DATA);
      }
    gcry_sexp_release (s_key); s_key = NULL;
  
    // EDITED FOR VANITY
    // Generate an ecc public key from the public part.
    err = ecckey_from_sexp (pk->pkey, s_public, algo);
    if (err)
      {
        log_error ("key_from_sexp failed: %s\n", gpg_strerror (err) );
        gcry_sexp_release (s_public);
        //free_public_key (pk); // Vanity: This function doesn't exist here.
                                // Accept the minor memory leak.
        return err;
      }
  
    // Range over 2 million generation seconds between the past and now.
    for (tmpstamp = lowertime; tmpstamp <= timestamp; ++tmpstamp) {
      pk->timestamp = tmpstamp;
      fp = fingerprint_from_pk(pk, fp, NULL);
      keyid = keyid_from_pk(pk, NULL);
      ++iterations;
      /*if ((keyid & 0xFFFF) == 0xCAFE ||
          (keyid & 0xFFFF000) == 0xF00D000 {*/
      if (keyid == 0xF00DF00D ||
          keyid == 0xDEADBEEF) {
        match = 1; // Not really needed anymore since the goto.
        goto store; // Break out of double loop, prevent releasing of s_private
                    // and s_public.
      } else {
        if (iterations % 1000000 == 0) {
          log_debug("Progressed through %llu iterations.\n", iterations);
        }
      }
    }
    gcry_sexp_release (s_private);
    gcry_sexp_release (s_public);
  }

store:
  log_debug("Hit desired key %X after %llu iterations!\n", keyid, iterations);
  gcry_sexp_release (s_keyparam);
  // VANITY EDITS END

  /* store the secret key */
  if (DBG_CRYPTO)
    log_debug ("storing private key\n");
  rc = store_key (s_private, passphrase, 0, ctrl->s2k_count);
  if (!rc)
    {
      if (!cache_nonce)
        {
          char tmpbuf[12];
          gcry_create_nonce (tmpbuf, 12);
          cache_nonce = bin2hex (tmpbuf, 12, NULL);
        }
      if (cache_nonce
          && !no_protection
          && !agent_put_cache (cache_nonce, CACHE_MODE_NONCE,
                               passphrase, ctrl->cache_ttl_opt_preset))
        agent_write_status (ctrl, "CACHE_NONCE", cache_nonce, NULL);
      if (preset && !no_protection)
	{
	  unsigned char grip[20];
	  char hexgrip[40+1];
	  if (gcry_pk_get_keygrip (s_private, grip))
	    {
	      bin2hex(grip, 20, hexgrip);
	      rc = agent_put_cache (hexgrip, CACHE_MODE_ANY, passphrase,
                                    ctrl->cache_ttl_opt_preset);
	    }
	}
    }
  xfree (passphrase_buffer);
  passphrase_buffer = NULL;
  passphrase = NULL;
  gcry_sexp_release (s_private);
  if (rc)
    {
      gcry_sexp_release (s_public);
      return rc;
    }

  /* return the public key */
  if (DBG_CRYPTO)
    log_debug ("returning public key\n");
  len = gcry_sexp_sprint (s_public, GCRYSEXP_FMT_CANON, NULL, 0);
  assert (len);
  buf = xtrymalloc (len);
  if (!buf)
    {
      gpg_error_t tmperr = out_of_core ();
      gcry_sexp_release (s_private);
      gcry_sexp_release (s_public);
      return tmperr;
    }
  len = gcry_sexp_sprint (s_public, GCRYSEXP_FMT_CANON, buf, len);
  assert (len);
  put_membuf (outbuf, buf, len);
  gcry_sexp_release (s_public);
  xfree (buf);

  return 0;
}



/* Apply a new passphrase to the key S_SKEY and store it.  If
   PASSPHRASE_ADDR and *PASSPHRASE_ADDR are not NULL, use that
   passphrase.  If PASSPHRASE_ADDR is not NULL store a newly entered
   passphrase at that address. */
gpg_error_t
agent_protect_and_store (ctrl_t ctrl, gcry_sexp_t s_skey,
                         char **passphrase_addr)
{
  gpg_error_t err;

  if (passphrase_addr && *passphrase_addr)
    {
      /* Take an empty string as request not to protect the key.  */
      err = store_key (s_skey, **passphrase_addr? *passphrase_addr:NULL, 1,
	      ctrl->s2k_count);
    }
  else
    {
      char *pass = NULL;

      if (passphrase_addr)
        {
          xfree (*passphrase_addr);
          *passphrase_addr = NULL;
        }
      err = agent_ask_new_passphrase (ctrl,
                                      _("Please enter the new passphrase"),
                                      &pass);
      if (!err)
        err = store_key (s_skey, pass, 1, ctrl->s2k_count);
      if (!err && passphrase_addr)
        *passphrase_addr = pass;
      else
        xfree (pass);
    }

  return err;
}
