/*
 * ocra.c - implementation of the OATH OCRA algorithm
 * Copyright (C) 2013 Fabian Grünbichler
 * Copyright (C) 2013 Simon Josefsson
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

#include <config.h>

#include "oath.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include "hotp.h"
#include "gc.h"

static int
map_hash (int h)
{
  /* If you change this function, make sure to align
     oath_ocra_cryptofunction_t and oath_ocra_passwordhash_t; these
     values are overloaded.  */
  switch (h)
    {
    case 1:
      return 1;
    case 256:
      return 2;
    case 512:
      return 3;
    default:
      return 0;
    }
}

static int
hashlen (int h)
{
  switch (h)
    {
    case 1:
      return GC_SHA1_DIGEST_SIZE;
    case 2:
      return GC_SHA256_DIGEST_SIZE;
    case 3:
      return GC_SHA512_DIGEST_SIZE;
    default:
      return 0;
    }
}

static int
map_challtype (char c)
{
  switch (c)
    {
    case 'A':
      return OATH_OCRA_CHALLENGE_ALPHANUM;
    case 'N':
      return OATH_OCRA_CHALLENGE_NUM;
    case 'H':
      return OATH_OCRA_CHALLENGE_HEX;
    default:
      return -1;
    }
}

static int
map_timestep (unsigned G, char Gunit)
{
  switch (Gunit)
    {
    case 'S':
      if (G == 0 || G > 59)
	return -1;
      break;

    case 'M':
      if (G == 0 || G > 59)
	return -1;
      G *= 60;
      break;

    case 'H':
      /* RFC 6287 says H=00 is permitted but that is nonsensical. */
      if (G == 0 || G > 48)
	return -1;
      G *= 60 * 60;
      break;

    default:
      return -1;
    }

  return G;
}

struct oath_ocrasuite_st
{
  /* A copy of the OCRASuite string.  */
  char ocrasuite_str[OATH_OCRASUITE_MAXLEN + 1];

  /* Defines which CryptoFunction is used to calculate the OCRA value
     is based. */
  oath_ocra_cryptofunction_t ocra_cf;

  /* Length of OCRA value (0 == no truncation, full HMAC length). */
  unsigned digits;

  /* Flag indicating whether a counter value is used as data input. */
  bool use_counter;

  /* Defines challenge format, see %oath_ocra_challenge_format_t. */
  oath_ocra_challenge_format_t challenge_format;

  /* Defines length of one challenge string. */
  size_t challenge_length;

  /* Defines which password hash function is used.  OATH_OCRA_PH_NONE
     means no password hash is included as data input. */
  oath_ocra_passwordhash_t password_hash;

  /* Divisor used to calculate timesteps passed since beginning of
     epoch (0 means no timestamp included as data input). */
  unsigned time_step_size;

  /* Number of bytes of session information used as data input. */
  size_t session_length;

  /* Total length of data input (in bytes). */
  size_t datainput_length;
};

static int
parse_ocrasuite (const char *ocrasuite, oath_ocrasuite_t * ocrasuite_info)
{
  const char *tmp;
  char f, Gunit;
  unsigned h, n, xx, nnn, G, consumed;

  memset (ocrasuite_info, 0, sizeof (*ocrasuite_info));

  if (strlen (ocrasuite) >= OATH_OCRASUITE_MAXLEN)
    return OATH_SUITE_PARSE_ERROR;
  strcpy (ocrasuite_info->ocrasuite_str, ocrasuite);

  ocrasuite_info->datainput_length = strlen (ocrasuite) + 1
    + OATH_CHALLENGE_MAXLEN;

  if (sscanf (ocrasuite, "OCRA-1:HOTP-SHA%u-%u:%n", &h, &n, &consumed) != 2)
    return OATH_SUITE_PARSE_ERROR;

  ocrasuite_info->ocra_cf = map_hash (h);
  if (ocrasuite_info->ocra_cf == 0)
    return OATH_SUITE_PARSE_ERROR;

  if (n != 0 && (n < 4 || n > 10))
    return OATH_SUITE_PARSE_ERROR;
  ocrasuite_info->digits = n;

  tmp = ocrasuite + consumed;
  if (strncmp (tmp, "C-", 2) == 0)
    {
      ocrasuite_info->datainput_length += 8;
      ocrasuite_info->use_counter = true;
      tmp += 2;
    }

  if (sscanf (tmp, "Q%c%02u-PSHA%u-S%03u-T%u%[HMS]%n",
	      &f, &xx, &h, &nnn, &G, &Gunit, &consumed) == 6)
    {
    }
  else if (sscanf (tmp, "Q%c%02u-PSHA%u%n", &f, &xx, &h, &consumed) == 3)
    {
      G = 0;
      nnn = 0;
    }
  else if (sscanf (tmp, "Q%c%02u-T%02u%[HMS]%n",
		   &f, &xx, &G, &Gunit, &consumed) == 4)
    {
      h = 0;
      nnn = 0;
    }
  else if (sscanf (tmp, "Q%c%02u%n", &f, &xx, &consumed) == 2)
    {
      G = 0;
      h = 0;
      nnn = 0;
    }
  else
    return OATH_SUITE_PARSE_ERROR;

  if (tmp[consumed] != '\0')
    return OATH_SUITE_PARSE_ERROR;

  ocrasuite_info->challenge_format = map_challtype (f);
  if ((int) ocrasuite_info->challenge_format == -1)
    return OATH_SUITE_PARSE_ERROR;

  if (xx < 4 || xx > 64)
    return OATH_SUITE_PARSE_ERROR;
  ocrasuite_info->challenge_length = xx;

  if (nnn > 512)
    return OATH_SUITE_PARSE_ERROR;
  ocrasuite_info->session_length = nnn;
  ocrasuite_info->datainput_length += nnn;

  if (h)
    {
      int len;

      ocrasuite_info->password_hash = map_hash (h);
      len = hashlen (ocrasuite_info->password_hash);
      if (ocrasuite_info->password_hash == 0 || len == 0)
	return OATH_SUITE_PARSE_ERROR;
      ocrasuite_info->datainput_length += len;
    }

  if (G)
    {
      ocrasuite_info->time_step_size = map_timestep (G, Gunit);
      if ((int) ocrasuite_info->time_step_size == -1)
	return OATH_SUITE_PARSE_ERROR;
      ocrasuite_info->datainput_length += 8;
    }

  return OATH_OK;
}

/**
 * oath_ocrasuite_parse:
 * @ocrasuite: OCRASuite string to be parsed.
 * @osh: Output pointer to OCRASuite handle.
 *
 * Parses the zero-terminated string @ocrasuite_string, storing the
 * results in the @osh handle.  OCRA Suite strings are explained in
 * RFC 6287.  Two example strings would be
 * "OCRA-1:HOTP-SHA1-4:QH8-S512" and
 * "OCRA-1:HOTP-SHA512-8:C-QN08-PSHA1".
 *
 * Returns: On success, %OATH_OK (zero) is returned, otherwise an
 * error code is returned.
 *
 * Since: 3.0.0
 **/
int
oath_ocrasuite_parse (const char *ocrasuite, oath_ocrasuite_t ** osh)
{
  int rc;

  if (ocrasuite == NULL || osh == NULL)
    return OATH_SUITE_PARSE_ERROR;

  *osh = calloc (1, sizeof (**osh));
  if (*osh == NULL)
    return OATH_MALLOC_ERROR;

  rc = parse_ocrasuite (ocrasuite, *osh);
  if (rc != OATH_OK)
    {
      free (*osh);
      return rc;
    }

  return OATH_OK;
}

/**
 * oath_ocrasuite_done:
 * @osh: OCRASuite handle.
 *
 * Releases all resources associated with the given @osh OCRASuite
 * handle.
 *
 * Since: 3.0.0
 **/
void
oath_ocrasuite_done (oath_ocrasuite_t * osh)
{
  free (osh);
}

/**
 * oath_ocrasuite_get_cryptofunction:
 * @osh: OCRASuite handle.
 *
 * Get the CryptoFunction.
 *
 * Returns: An %oath_ocra_cryptofunction_t value.
 *
 * Since: 3.0.0
 **/
oath_ocra_cryptofunction_t
oath_ocrasuite_get_cryptofunction (oath_ocrasuite_t * osh)
{
  return osh->ocra_cf;
}

/**
 * oath_ocrasuite_get_cryptofunction_digits:
 * @osh: OCRASuite handle.
 *
 * Get the output size of the OCRA code, e.g., 6 means the output code
 * is 6 digits.
 *
 * Returns: Size of output code.
 *
 * Since: 3.0.0
 **/
unsigned
oath_ocrasuite_get_cryptofunction_digits (oath_ocrasuite_t * osh)
{
  return osh->digits;
}

/**
 * oath_ocrasuite_get_counter:
 * @osh: OCRASuite handle.
 *
 * Get whether a counter is used for the OCRASuite.
 *
 * Returns: true if a counter is used, false otherwise.
 *
 * Since: 3.0.0
 **/
bool
oath_ocrasuite_get_counter (oath_ocrasuite_t * osh)
{
  return osh->use_counter;
}

/**
 * oath_ocrasuite_get_challenge_format:
 * @osh: OCRASuite handle.
 *
 * Get the challenge format in the @osh OCRASuite.
 *
 * Returns: a %oath_ocra_challenge_format_t value, e.g.,
 * #OATH_OCRA_CHALLENGE_ALPHANUM.
 *
 * Since: 3.0.0
 **/
oath_ocra_challenge_format_t
oath_ocrasuite_get_challenge_format (oath_ocrasuite_t * osh)
{
  return osh->challenge_format;
}

/**
 * oath_ocrasuite_get_challenge_length:
 * @osh: OCRASuite handle.
 *
 * Get the maximum length of the challenge of the OCRASuite, 04-64.
 *
 * Returns: challenge length.
 *
 * Since: 3.0.0
 **/
size_t
oath_ocrasuite_get_challenge_length (oath_ocrasuite_t * osh)
{
  return osh->challenge_length;
}

/**
 * oath_ocrasuite_get_password_hash:
 * @osh: OCRASuite handle.
 *
 * Get the hash function used to hash the PIN/password.
 *
 * Returns: a %oath_ocra_passwordhash_t value, e.g., #OATH_OCRA_PH_SHA1.
 *
 * Since: 3.0.0
 **/
oath_ocra_passwordhash_t
oath_ocrasuite_get_password_hash (oath_ocrasuite_t * osh)
{
  return osh->password_hash;
}

/**
 * oath_ocrasuite_get_session_length:
 * @osh: OCRASuite handle.
 *
 * Get the length of the session data in the OCRASuite.
 *
 * Returns: length of the session, typical values are 64, 128, 256 and
 * 512.
 *
 * Since: 3.0.0
 **/
size_t
oath_ocrasuite_get_session_length (oath_ocrasuite_t * osh)
{
  return osh->session_length;
}

/**
 * oath_ocrasuite_get_time_step:
 * @osh: OCRASuite handle.
 *
 * Get the size of one time step as specified in the OCRASuite.
 *
 * Returns: size of one time step in seconds.
 *
 * Since: 3.0.0
 **/
unsigned
oath_ocrasuite_get_time_step (oath_ocrasuite_t * osh)
{
  return osh->time_step_size;
}

/**
 * oath_ocra_challenge_generate:
 * @challtype: a %oath_ocra_challenge_format_t type, e.g., #OATH_OCRA_CHALLENGE_HEX.
 * @length: length of challenge to generate.
 * @challenge: Output buffer, needs space for 65 chars.
 *
 * Generates a (pseudo)random challenge string of length @length and
 * type @challtype.
 *
 * According to the RFC, challenges questions SHOULD be 20-byte values
 * and MUST be at least t-byte values where t stands for the
 * digit-length of the OCRA truncation output (i.e., @digits in a
 * parsed %oath_ocrasuite_t).
 *
 * Returns: %OATH_OK (zero) on success, an error code otherwise.
 *
 * Since: 3.0.0
 **/
int
oath_ocra_challenge_generate (oath_ocra_challenge_format_t challtype,
			      size_t length, char *challenge)
{
  const char *lookup =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  int wraplen;
  char *rng;
  uint8_t *p;
  size_t i;
  int rc;

  switch (challtype)
    {
    case OATH_OCRA_CHALLENGE_ALPHANUM:
      wraplen = strlen (lookup);
      break;

    case OATH_OCRA_CHALLENGE_NUM:
      wraplen = 10;
      break;

    case OATH_OCRA_CHALLENGE_HEX:
      wraplen = 16;
      break;

    default:
      return OATH_INVALID_DIGITS;
      break;
    }

  /* XXX: We could avoid this malloc by re-using the challenge buffer
     for temporary storage. */

  rng = malloc (length);
  if (rng == NULL)
    return OATH_MALLOC_ERROR;

  rc = gc_nonce (rng, length);
  if (rc != GC_OK)
    {
      free (rng);
      return OATH_CRYPTO_ERROR;
    }

  p = (uint8_t *) rng;
  for (i = 0; i < length; i++)
    *challenge++ = lookup[*p++ % wraplen];
  *challenge = '\0';

  free (rng);

  return OATH_OK;
}

/**
 * oath_ocra_challenge_generate_suitestr:
 * @ocrasuite: String with OCRA Suite description.
 * @challenge: Output buffer, needs space for the challenge length
 *   in @ocrasuite plus one, which is max 65 bytes.
 *
 * Generates a (pseudo)random challenge string depending on the type
 * and length given by @ocrasuite.
 *
 * Returns: %OATH_OK (zero) on success, an error code otherwise.
 *
 * Since: 3.0.0
 **/
int
oath_ocra_challenge_generate_suitestr (const char *ocrasuite, char *challenge)
{
  int rc;
  oath_ocrasuite_t os;

  rc = parse_ocrasuite (ocrasuite, &os);
  if (rc != OATH_OK)
    return rc;

  return oath_ocra_challenge_generate (os.challenge_format,
				       os.challenge_length, challenge);
}

/**
 * oath_ocra_challenge_convert:
 * @nchalls: Number of elements in @challtypes and @challstrings.
 * @challtypes: Array of size @nchalls with %oath_ocra_challenge_format_t types.
 * @challstrings: Array of size @nchalls with challenge strings.
 * @output_challenge: 128-byte output buffer with binary challenge data.
 *
 * Convert challenge question(s) to binary and concatenate them to
 * form the 128-byte binary challenge Q value.  The challenge types
 * are given in the @challtypes array, which holds
 * %oath_ocra_challenge_format_t values, and the challenge strings are given
 * in the @challstrings array.  The function will decode and
 * concatenate the first @nchalls elements of the arrays, so both
 * arrays must be at least this large.
 *
 * Returns: %OATH_OK (zero) on success, an error code otherwise.
 *
 * Since: 3.0.0
 **/
int
oath_ocra_challenge_convert (size_t nchalls,
			     const oath_ocra_challenge_format_t * challtypes,
			     const char * const *challstrings,
			     char *output_challenge)
{
  int curr_pos = 0;
  size_t i = 0, challenge_binary_length = 0;

  while (i < nchalls)
    {
      switch (challtypes[i])
	{
	case OATH_OCRA_CHALLENGE_NUM:
	  {
	    unsigned long int num_value =
	      strtoul (challstrings[i], NULL, 10);
	    char *temp = malloc (strlen (challstrings[i]) + 2);
	    size_t hex_length;

	    if (temp == NULL)
	      return OATH_MALLOC_ERROR;

	    sprintf (temp, "%lX", num_value);

	    hex_length = strlen (temp);

	    if (hex_length % 2 == 1)
	      {
		temp[hex_length] = '0';
		temp[hex_length + 1] = '\0';
	      }

	    oath_hex2bin (temp, NULL, &challenge_binary_length);

	    if (curr_pos + challenge_binary_length >= OATH_CHALLENGE_MAXLEN)
	      {
		free (temp);
		return OATH_INVALID_OCRA_CHALLENGE;
	      }

	    oath_hex2bin (temp,
			  output_challenge + curr_pos,
			  &challenge_binary_length);

	    free (temp);

	    curr_pos += challenge_binary_length;
	  }
	  break;

	case OATH_OCRA_CHALLENGE_HEX:
	  {
	    size_t challenge_length = strlen (challstrings[i]);
	    char *temp = malloc (challenge_length + 2);

	    if (temp == NULL)
		return OATH_MALLOC_ERROR;

	    memcpy (temp, challstrings[i], challenge_length);
	    temp[challenge_length] = '\0';

	    if (challenge_length % 2 == 1)
	      {
		temp[challenge_length] = '0';
		temp[challenge_length + 1] = '\0';
	      }

	    oath_hex2bin (temp, NULL, &challenge_binary_length);

	    if (curr_pos + challenge_binary_length >= OATH_CHALLENGE_MAXLEN)
	      {
		free (temp);
		return OATH_INVALID_OCRA_CHALLENGE;
	      }

	    oath_hex2bin (temp,
			  output_challenge +
			  curr_pos, &challenge_binary_length);

	    free (temp);

	    curr_pos += challenge_binary_length;
	  }
	  break;

	case OATH_OCRA_CHALLENGE_ALPHANUM:
	  {
	    if (curr_pos + strlen (challstrings[i]) >= OATH_CHALLENGE_MAXLEN)
	      return OATH_INVALID_OCRA_CHALLENGE;

	    memcpy (output_challenge +
		    curr_pos,
		    challstrings[i], strlen (challstrings[i]));

	    curr_pos += strlen (challstrings[i]);
	  }
	  break;

	default:
	  return OATH_INVALID_OCRA_CHALLENGE;
	  break;
	}
      i++;
    }

  memset (output_challenge + curr_pos, '\0',
	  (OATH_CHALLENGE_MAXLEN - curr_pos));

  return OATH_OK;
}

static int
map_cf (oath_ocra_cryptofunction_t cf)
{
  switch (cf)
    {
    case OATH_OCRA_CF_HOTP_SHA256:
      return OATH_TOTP_HMAC_SHA256;
    case OATH_OCRA_CF_HOTP_SHA512:
      return OATH_TOTP_HMAC_SHA512;
    default:
      return 0;
    }
}

/**
 * oath_ocra_generate:
 * @secret: The shared secret string.
 * @secret_length: Length of @secret.
 * @ocrasuite: the OCRASuite in the form of a parsed %oath_ocrasuite_t.
 * @counter: Counter value, optional (see @ocrasuite).
 * @challenges: 128-byte binary client/server challenge values, mandatory.
 * @password_hash: Hashed password value, optional (see @ocrasuite).
 * @session: Static data about current session, optional (see @ocra-suite).
 * @now: Current timestamp, optional (see @ocrasuite).
 * @output_ocra: Output buffer.
 *
 * Generate a truncated hash-value used for challenge-response-based
 * authentication according to the OCRA algorithm described in RFC
 * 6287.  Besides the mandatory 128-byte @challenges, additional input
 * is optional, but mandated by the OCRASuite value.
 *
 * The @ocrasuite describes which mode of OCRA is to be
 * used. Furthermore it contains information about which of the
 * possible optional data inputs are to be used, and how.
 *
 * Note that challenges must be in the prepared binary form before
 * being passed in @challenges, see oath_ocra_challenge_convert().
 *
 * The output buffer @output_ocra must have room for at least as many
 * digits as specified as part of @ocrasuite, plus one terminating NUL
 * char.  Use oath_ocrasuite_get_cryptofunction_digits() to find out
 * how many digits.  Currently the code only supports 6, 7, and 8
 * digit outputs.
 *
 * Returns: on success, %OATH_OK (zero) is returned, otherwise an
 * error code is returned.
 *
 * Since: 3.0.0
 **/
int
oath_ocra_generate (const char *secret,
		    size_t secret_length,
		    oath_ocrasuite_t *ocrasuite,
		    uint64_t counter,
		    const char *challenges,
		    const char *password_hash,
		    const char *session,
		    time_t now,
		    char *output_ocra)
{
  int rc;
  char *byte_array = NULL;
  char *curr_ptr = NULL;
  uint64_t time_steps = 0;
  char tmp_str[17];
  size_t tmp_len;
  int flags = map_cf (ocrasuite->ocra_cf);

  if (challenges == NULL)
    return OATH_SUITE_MISMATCH_ERROR;

  if (ocrasuite->password_hash != OATH_OCRA_PH_NONE
      && password_hash == NULL)
    return OATH_SUITE_MISMATCH_ERROR;

  if (ocrasuite->session_length > 0 && session == NULL)
    return OATH_SUITE_MISMATCH_ERROR;

  if (ocrasuite->session_length > 512)
    return OATH_SUITE_MISMATCH_ERROR;

  byte_array = malloc (ocrasuite->datainput_length);
  if (byte_array == NULL)
    return OATH_MALLOC_ERROR;

  curr_ptr = byte_array;
  memcpy (curr_ptr,
	  ocrasuite->ocrasuite_str, strlen (ocrasuite->ocrasuite_str));
  curr_ptr += strlen (ocrasuite->ocrasuite_str);
  curr_ptr[0] = '\0';
  curr_ptr++;

  if (ocrasuite->use_counter)
    {
      tmp_len = 8;
      sprintf (tmp_str, "%016" PRIX64, counter);
      oath_hex2bin (tmp_str, curr_ptr, &tmp_len);
      curr_ptr += 8;
    }

  memcpy (curr_ptr, challenges, OATH_CHALLENGE_MAXLEN);
  curr_ptr += OATH_CHALLENGE_MAXLEN;

  if (ocrasuite->password_hash)
    {
      int len = hashlen (ocrasuite->password_hash);
      memcpy (curr_ptr, password_hash, len);
      curr_ptr += len;
    }

  if (ocrasuite->session_length > 0)
    {
      memcpy (curr_ptr, session, ocrasuite->session_length);
      curr_ptr += ocrasuite->session_length;
    }

  if (ocrasuite->time_step_size != 0)
    {
      time_steps = now / ocrasuite->time_step_size;
      tmp_len = 8;
      sprintf (tmp_str, "%016" PRIX64, time_steps);
      oath_hex2bin (tmp_str, curr_ptr, &tmp_len);
    }

  rc = _oath_hotp_generate3 (secret,
			     secret_length,
			     byte_array,
			     ocrasuite->datainput_length,
			     ocrasuite->digits, flags, output_ocra);

  free (byte_array);

  return rc;
}

/**
 * oath_ocra_validate:
 * @secret: The shared secret string.
 * @secret_length: Length of @secret.
 * @ocrasuite: the OCRASuite in the form of a parsed %oath_ocrasuite_t.
 * @counter: Counter value, optional (see @ocrasuite).
 * @challenges: 128-byte binary client/server challenge values, mandatory.
 * @password_hash: Hashed password value, optional (see @ocrasuite).
 * @session: Static data about current session, optional (see @ocra-suite).
 * @now: Current timestamp, optional (see @ocrasuite).
 * @ocra_value: OCRA value to validate against.
 *
 * Validates a given OCRA value @ocra_value by generating an OCRA code
 * using the given parameters and comparing the result.
 *
 * Returns: %OATH_OK (zero) on successful validation, if the OCRA
 *   value is incorrect %OATH_INVALID_OTP is returned, otherwise an
 *   error code.
 *
 * Since: 3.0.0
 **/
int
oath_ocra_validate (const char *secret,
		    size_t secret_length,
		    oath_ocrasuite_t *ocrasuite,
		    uint64_t counter,
		    const char *challenges,
		    const char *password_hash,
		    const char *session,
		    time_t now,
		    const char *ocra_value)
{

  int rc;
  char generated_ocra[11];	/* max 10 digits */

  rc = oath_ocra_generate (secret,
			   secret_length,
			   ocrasuite,
			   counter,
			   challenges,
			   password_hash,
			   session,
			   now,
			   generated_ocra);
  if (rc != OATH_OK)
    return rc;

  if (strcmp (generated_ocra, ocra_value) != 0)
    return OATH_INVALID_OTP;

  return OATH_OK;
}
