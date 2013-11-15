/*
 * tst_ocra_algo.c - self-tests for liboath OCRA algorithm functions
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

const char *pHash =
  "\x71\x10\xed\xa4\xd0\x9e\x06\x2a\xa5\xe4"
  "\xa3\x90\xb0\xa5\x72\xac\x0d\x2c\x02\x20";

#define STANDARD_20BYTE_KEY "12345678901234567890"
#define STANDARD_32BYTE_KEY "12345678901234567890123456789012"
#define STANDARD_64BYTE_KEY \
  "1234567890123456789012345678901234567890123456789012345678901234"

static const struct
{
  char *secret;
  char *ocra_suite;
  uint64_t counter;
  const char *challenge_strings[2];
  size_t number_of_challenges;
  oath_ocra_challenge_format_t challenge_types[2];
  char challenges_binary[OATH_CHALLENGE_MAXLEN];
  char *session;
  time_t now;
  char *ocra;
} tv[] =
{
  /* Self-tests from RFC 6287. */

  /* C.1.  One-Way Challenge Response */

  /*
     Standard 20Byte key:
     3132333435363738393031323334353637383930
     +-----------------+----------+------------+
     |       Key       |     Q    | OCRA Value |
     +-----------------+----------+------------+
     | Standard 20Byte | 00000000 |   237653   |
     | Standard 20Byte | 11111111 |   243178   |
     | Standard 20Byte | 22222222 |   653583   |
     | Standard 20Byte | 33333333 |   740991   |
     | Standard 20Byte | 44444444 |   608993   |
     | Standard 20Byte | 55555555 |   388898   |
     | Standard 20Byte | 66666666 |   816933   |
     | Standard 20Byte | 77777777 |   224598   |
     | Standard 20Byte | 88888888 |   750600   |
     | Standard 20Byte | 99999999 |   294470   |
     +-----------------+----------+------------+
     OCRA-1:HOTP-SHA1-6:QN08
   */

#define TV1(Q,BINQ,OTP)						\
  { STANDARD_20BYTE_KEY, "OCRA-1:HOTP-SHA1-6:QN08", 0,		\
    { Q }, 1, { OATH_OCRA_CHALLENGE_NUM}, BINQ, NULL, 0, OTP}

  TV1("00000000", "",			"237653"),
  TV1("11111111", "\xa9\x8a\xc7",	"243178"),
  TV1("22222222", "\x15\x31\x58\xe0",	"653583"),
  TV1("33333333", "\x1f\xca\x05\x50",	"740991"),
  TV1("44444444", "\x2a\x62\xb1\xc0",	"608993"),
  TV1("55555555", "\x34\xfb\x5e\x30",	"388898"),
  TV1("66666666", "\x3f\x94\x0a\xa0",	"816933"),
  TV1("77777777", "\x4a\x2c\xb7\x10",	"224598"),
  TV1("88888888", "\x54\xc5\x63\x80",	"750600"),
  TV1("99999999", "\x5f\x5e\x0f\xf0",	"294470"),

  /*
    +-----------------+---+----------+------------+
    |       Key       | C |     Q    | OCRA Value |
    +-----------------+---+----------+------------+
    | Standard 32Byte | 0 | 12345678 |  65347737  |
    | Standard 32Byte | 1 | 12345678 |  86775851  |
    | Standard 32Byte | 2 | 12345678 |  78192410  |
    | Standard 32Byte | 3 | 12345678 |  71565254  |
    | Standard 32Byte | 4 | 12345678 |  10104329  |
    | Standard 32Byte | 5 | 12345678 |  65983500  |
    | Standard 32Byte | 6 | 12345678 |  70069104  |
    | Standard 32Byte | 7 | 12345678 |  91771096  |
    | Standard 32Byte | 8 | 12345678 |  75011558  |
    | Standard 32Byte | 9 | 12345678 |  08522129  |
    +-----------------+---+----------+------------+
    OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1
   */

#define TV2(C,OTP)							\
  { STANDARD_32BYTE_KEY, "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1", C,	\
    { "12345678" }, 1, { OATH_OCRA_CHALLENGE_NUM}, "\xbc\x61\x4e",	\
  NULL, 0, OTP}

  TV2(0, "65347737"),
  TV2(1, "86775851"),
  TV2(2, "78192410"),
  TV2(3, "71565254"),
  TV2(4, "10104329"),
  TV2(5, "65983500"),
  TV2(6, "70069104"),
  TV2(7, "91771096"),
  TV2(8, "75011558"),
  TV2(9, "08522129"),

  /*
    +-----------------+----------+------------+
    |       Key       |     Q    | OCRA Value |
    +-----------------+----------+------------+
    | Standard 32Byte | 00000000 |  83238735  |
    | Standard 32Byte | 11111111 |  01501458  |
    | Standard 32Byte | 22222222 |  17957585  |
    | Standard 32Byte | 33333333 |  86776967  |
    | Standard 32Byte | 44444444 |  86807031  |
    +-----------------+----------+------------+
    OCRA-1:HOTP-SHA256-8:QN08-PSHA1
  */

#define TV3(Q,BINQ,OTP)							\
  { STANDARD_32BYTE_KEY, "OCRA-1:HOTP-SHA256-8:QN08-PSHA1", 0,	\
    { Q }, 1, { OATH_OCRA_CHALLENGE_NUM}, BINQ, NULL, 0, OTP}

  TV3("00000000", "",			"83238735"),
  TV3("11111111", "\xa9\x8a\xc7",	"01501458"),
  TV3("22222222", "\x15\x31\x58\xe0",	"17957585"),
  TV3("33333333", "\x1f\xca\x05\x50",	"86776967"),
  TV3("44444444", "\x2a\x62\xb1\xc0",	"86807031"),

  /*
    +-----------------+-------+----------+------------+
    |       Key       |   C   |     Q    | OCRA Value |
    +-----------------+-------+----------+------------+
    | Standard 64Byte | 00000 | 00000000 |  07016083  |
    | Standard 64Byte | 00001 | 11111111 |  63947962  |
    | Standard 64Byte | 00002 | 22222222 |  70123924  |
    | Standard 64Byte | 00003 | 33333333 |  25341727  |
    | Standard 64Byte | 00004 | 44444444 |  33203315  |
    | Standard 64Byte | 00005 | 55555555 |  34205738  |
    | Standard 64Byte | 00006 | 66666666 |  44343969  |
    | Standard 64Byte | 00007 | 77777777 |  51946085  |
    | Standard 64Byte | 00008 | 88888888 |  20403879  |
    | Standard 64Byte | 00009 | 99999999 |  31409299  |
    +-----------------+-------+----------+------------+
    OCRA-1:HOTP-SHA512-8:C-QN08
  */

#define TV4(C,Q,BINQ,OTP)					\
  { STANDARD_64BYTE_KEY, "OCRA-1:HOTP-SHA512-8:C-QN08", C, \
    { Q }, 1, { OATH_OCRA_CHALLENGE_NUM}, BINQ, NULL, 0, OTP}

  TV4(0, "00000000", "",			"07016083"),
  TV4(1, "11111111", "\xa9\x8a\xc7",		"63947962"),
  TV4(2, "22222222", "\x15\x31\x58\xe0",	"70123924"),
  TV4(3, "33333333", "\x1f\xca\x05\x50",	"25341727"),
  TV4(4, "44444444", "\x2a\x62\xb1\xc0",	"33203315"),
  TV4(5, "55555555", "\x34\xfb\x5e\x30",	"34205738"),
  TV4(6, "66666666", "\x3f\x94\x0a\xa0",	"44343969"),
  TV4(7, "77777777", "\x4a\x2c\xb7\x10",	"51946085"),
  TV4(8, "88888888", "\x54\xc5\x63\x80",	"20403879"),
  TV4(9, "99999999", "\x5f\x5e\x0f\xf0",	"31409299"),

  /*
    +-----------------+----------+---------+------------+
    |       Key       |     Q    |    T    | OCRA Value |
    +-----------------+----------+---------+------------+
    | Standard 64Byte | 00000000 | 132d0b6 |  95209754  |
    | Standard 64Byte | 11111111 | 132d0b6 |  55907591  |
    | Standard 64Byte | 22222222 | 132d0b6 |  22048402  |
    | Standard 64Byte | 33333333 | 132d0b6 |  24218844  |
    | Standard 64Byte | 44444444 | 132d0b6 |  36209546  |
    +-----------------+----------+---------+------------+
    OCRA-1:HOTP-SHA512-8:QN08-T1M

   */

#define TV5(Q,BINQ,T,OTP)					\
  { STANDARD_64BYTE_KEY, "OCRA-1:HOTP-SHA512-8:QN08-T1M", 0,	\
  { Q }, 1, { OATH_OCRA_CHALLENGE_NUM}, BINQ, NULL, T, OTP}

  TV5("00000000", "",			0x132d0b6 * 60, "95209754"),
  TV5("11111111", "\xa9\x8a\xc7",	0x132d0b6 * 60, "55907591"),
  TV5("22222222", "\x15\x31\x58\xe0",	0x132d0b6 * 60, "22048402"),
  TV5("33333333", "\x1f\xca\x05\x50",	0x132d0b6 * 60, "24218844"),
  TV5("44444444", "\x2a\x62\xb1\xc0",	0x132d0b6 * 60, "36209546"),

  /* C.2.  Mutual Challenge-Response */

  /*
    OCRASuite (server computation) = OCRA-1:HOTP-SHA256-8:QA08
    OCRASuite (client computation) = OCRA-1:HOTP-SHA256-8:QA08

    +-----------------+------------------+------------+
    |       Key       |         Q        | OCRA Value |
    +-----------------+------------------+------------+
    | Standard 32Byte | CLI22220SRV11110 |  28247970  |
    | Standard 32Byte | CLI22221SRV11111 |  01984843  |
    | Standard 32Byte | CLI22222SRV11112 |  65387857  |
    | Standard 32Byte | CLI22223SRV11113 |  03351211  |
    | Standard 32Byte | CLI22224SRV11114 |  83412541  |
    +-----------------+------------------+------------+
    Server -- OCRA-1:HOTP-SHA256-8:QA08
   */

#define TV6(Q1,Q2,OTP,BINQ)						\
  { STANDARD_32BYTE_KEY, "OCRA-1:HOTP-SHA256-8:QA08", 0,		\
      { Q1, Q2 }, 2, { OATH_OCRA_CHALLENGE_ALPHANUM,			\
      OATH_OCRA_CHALLENGE_ALPHANUM}, BINQ, NULL, 0, OTP}

  TV6("CLI22220", "SRV11110", "28247970",
      "\x43\x4c\x49\x32\x32\x32\x32\x30\x53\x52\x56\x31\x31\x31\x31\x30"),
  TV6("CLI22221", "SRV11111", "01984843",
      "\x43\x4c\x49\x32\x32\x32\x32\x31\x53\x52\x56\x31\x31\x31\x31\x31"),
  TV6("CLI22222", "SRV11112", "65387857",
      "\x43\x4c\x49\x32\x32\x32\x32\x32\x53\x52\x56\x31\x31\x31\x31\x32"),
  TV6("CLI22223", "SRV11113", "03351211",
      "\x43\x4c\x49\x32\x32\x32\x32\x33\x53\x52\x56\x31\x31\x31\x31\x33"),
  TV6("CLI22224", "SRV11114", "83412541",
      "\x43\x4c\x49\x32\x32\x32\x32\x34\x53\x52\x56\x31\x31\x31\x31\x34"),

  /*
    +-----------------+------------------+------------+
    |       Key       |         Q        | OCRA Value |
    +-----------------+------------------+------------+
    | Standard 32Byte | SRV11110CLI22220 |  15510767  |
    | Standard 32Byte | SRV11111CLI22221 |  90175646  |
    | Standard 32Byte | SRV11112CLI22222 |  33777207  |
    | Standard 32Byte | SRV11113CLI22223 |  95285278  |
    | Standard 32Byte | SRV11114CLI22224 |  28934924  |
    +-----------------+------------------+------------+
    Client -- OCRA-1:HOTP-SHA256-8:QA08
   */

#define TV7(Q1,Q2,OTP,BINQ)						\
  { STANDARD_32BYTE_KEY, "OCRA-1:HOTP-SHA256-8:QA08", 0,		\
    { Q1, Q2 }, 2, { OATH_OCRA_CHALLENGE_ALPHANUM,			\
		     OATH_OCRA_CHALLENGE_ALPHANUM}, BINQ, NULL, 0, OTP}

  TV7("SRV11110", "CLI22220", "15510767",
      "\x53\x52\x56\x31\x31\x31\x31\x30\x43\x4c\x49\x32\x32\x32\x32\x30"),
  TV7("SRV11111", "CLI22221", "90175646",
      "\x53\x52\x56\x31\x31\x31\x31\x31\x43\x4c\x49\x32\x32\x32\x32\x31"),
  TV7("SRV11112", "CLI22222", "33777207",
      "\x53\x52\x56\x31\x31\x31\x31\x32\x43\x4c\x49\x32\x32\x32\x32\x32"),
  TV7("SRV11113", "CLI22223", "95285278",
      "\x53\x52\x56\x31\x31\x31\x31\x33\x43\x4c\x49\x32\x32\x32\x32\x33"),
  TV7("SRV11114", "CLI22224", "28934924",
      "\x53\x52\x56\x31\x31\x31\x31\x34\x43\x4c\x49\x32\x32\x32\x32\x34"),

  /*
    OCRASuite (server computation) = OCRA-1:HOTP-SHA512-8:QA08
    OCRASuite (client computation) = OCRA-1:HOTP-SHA512-8:QA08-PSHA1

    +-----------------+------------------+------------+
    |       Key       |         Q        | OCRA Value |
    +-----------------+------------------+------------+
    | Standard 64Byte | CLI22220SRV11110 |  79496648  |
    | Standard 64Byte | CLI22221SRV11111 |  76831980  |
    | Standard 64Byte | CLI22222SRV11112 |  12250499  |
    | Standard 64Byte | CLI22223SRV11113 |  90856481  |
    | Standard 64Byte | CLI22224SRV11114 |  12761449  |
    +-----------------+------------------+------------+
    Server -- OCRA-1:HOTP-SHA512-8:QA08
   */

#define TV8(Q1,Q2,OTP,BINQ)						\
  { STANDARD_64BYTE_KEY, "OCRA-1:HOTP-SHA512-8:QA08", 0, \
    { Q1, Q2 }, 2, { OATH_OCRA_CHALLENGE_ALPHANUM,			\
		     OATH_OCRA_CHALLENGE_ALPHANUM}, BINQ, NULL, 0, OTP}

  TV8("CLI22220", "SRV11110", "79496648",
      "\x43\x4c\x49\x32\x32\x32\x32\x30\x53\x52\x56\x31\x31\x31\x31\x30"),
  TV8("CLI22221", "SRV11111", "76831980",
      "\x43\x4c\x49\x32\x32\x32\x32\x31\x53\x52\x56\x31\x31\x31\x31\x31"),
  TV8("CLI22222", "SRV11112", "12250499",
      "\x43\x4c\x49\x32\x32\x32\x32\x32\x53\x52\x56\x31\x31\x31\x31\x32"),
  TV8("CLI22223", "SRV11113", "90856481",
      "\x43\x4c\x49\x32\x32\x32\x32\x33\x53\x52\x56\x31\x31\x31\x31\x33"),
  TV8("CLI22224", "SRV11114", "12761449",
      "\x43\x4c\x49\x32\x32\x32\x32\x34\x53\x52\x56\x31\x31\x31\x31\x34"),

  /*
    +-----------------+------------------+------------+
    |       Key       |         Q        | OCRA Value |
    +-----------------+------------------+------------+
    | Standard 64Byte | SRV11110CLI22220 |  18806276  |
    | Standard 64Byte | SRV11111CLI22221 |  70020315  |
    | Standard 64Byte | SRV11112CLI22222 |  01600026  |
    | Standard 64Byte | SRV11113CLI22223 |  18951020  |
    | Standard 64Byte | SRV11114CLI22224 |  32528969  |
    +-----------------+------------------+------------+
    Client -- OCRA-1:HOTP-SHA512-8:QA08-PSHA1
   */

#define TV9(Q1,Q2,OTP,BINQ)				 \
  { STANDARD_64BYTE_KEY, "OCRA-1:HOTP-SHA512-8:QA08-PSHA1", 0,		\
    { Q1, Q2 }, 2, { OATH_OCRA_CHALLENGE_ALPHANUM,			\
		     OATH_OCRA_CHALLENGE_ALPHANUM}, BINQ, NULL, 0, OTP}

  TV9("SRV11110", "CLI22220", "18806276",
      "\x53\x52\x56\x31\x31\x31\x31\x30\x43\x4c\x49\x32\x32\x32\x32\x30"),
  TV9("SRV11111", "CLI22221", "70020315",
      "\x53\x52\x56\x31\x31\x31\x31\x31\x43\x4c\x49\x32\x32\x32\x32\x31"),
  TV9("SRV11112", "CLI22222", "01600026",
      "\x53\x52\x56\x31\x31\x31\x31\x32\x43\x4c\x49\x32\x32\x32\x32\x32"),
  TV9("SRV11113", "CLI22223", "18951020",
      "\x53\x52\x56\x31\x31\x31\x31\x33\x43\x4c\x49\x32\x32\x32\x32\x33"),
  TV9("SRV11114", "CLI22224", "32528969",
      "\x53\x52\x56\x31\x31\x31\x31\x34\x43\x4c\x49\x32\x32\x32\x32\x34"),

  /* C.3.  Plain Signature */

  /*
    +-----------------+----------+------------+
    |       Key       |     Q    | OCRA Value |
    +-----------------+----------+------------+
    | Standard 32Byte | SIG10000 |  53095496  |
    | Standard 32Byte | SIG11000 |  04110475  |
    | Standard 32Byte | SIG12000 |  31331128  |
    | Standard 32Byte | SIG13000 |  76028668  |
    | Standard 32Byte | SIG14000 |  46554205  |
    +-----------------+----------+------------+
    OCRA-1:HOTP-SHA256-8:QA08
  */

#define TV10(Q,BINQ,OTP)						\
    { STANDARD_32BYTE_KEY, "OCRA-1:HOTP-SHA256-8:QA08", 0,	\
    { Q }, 1, { OATH_OCRA_CHALLENGE_ALPHANUM}, BINQ, NULL, 0, OTP}

  TV10("SIG10000", "\x53\x49\x47\x31\x30\x30\x30\x30", "53095496"),
  TV10("SIG11000", "\x53\x49\x47\x31\x31\x30\x30\x30", "04110475"),
  TV10("SIG12000", "\x53\x49\x47\x31\x32\x30\x30\x30", "31331128"),
  TV10("SIG13000", "\x53\x49\x47\x31\x33\x30\x30\x30", "76028668"),
  TV10("SIG14000", "\x53\x49\x47\x31\x34\x30\x30\x30", "46554205"),

  /*
    +-----------------+------------+---------+------------+
    |       Key       |      Q     |    T    | OCRA Value |
    +-----------------+------------+---------+------------+
    | Standard 64Byte | SIG1000000 | 132d0b6 |  77537423  |
    | Standard 64Byte | SIG1100000 | 132d0b6 |  31970405  |
    | Standard 64Byte | SIG1200000 | 132d0b6 |  10235557  |
    | Standard 64Byte | SIG1300000 | 132d0b6 |  95213541  |
    | Standard 64Byte | SIG1400000 | 132d0b6 |  65360607  |
    +-----------------+------------+---------+------------+
    OCRA-1:HOTP-SHA512-8:QA10-T1M
  */

#define TV11(Q,T,OTP,BINQ)					     \
  { STANDARD_64BYTE_KEY, "OCRA-1:HOTP-SHA512-8:QA10-T1M", 0, \
    { Q }, 1, { OATH_OCRA_CHALLENGE_ALPHANUM}, BINQ, NULL, T, OTP}

  TV11("SIG1000000", 0x132d0b6 * 60, "77537423",
       "\x53\x49\x47\x31\x30\x30\x30\x30\x30\x30"),
  TV11("SIG1100000", 0x132d0b6 * 60, "31970405",
       "\x53\x49\x47\x31\x31\x30\x30\x30\x30\x30"),
  TV11("SIG1200000", 0x132d0b6 * 60, "10235557",
       "\x53\x49\x47\x31\x32\x30\x30\x30\x30\x30"),
  TV11("SIG1300000", 0x132d0b6 * 60, "95213541",
       "\x53\x49\x47\x31\x33\x30\x30\x30\x30\x30"),
  TV11("SIG1400000", 0x132d0b6 * 60, "65360607",
       "\x53\x49\x47\x31\x34\x30\x30\x30\x30\x30"),
};


int
main (void)
{
  oath_rc rc;
  int i;

  rc = oath_init ();
  if (rc != OATH_OK)
    {
      printf ("oath_init: %d\n", rc);
      return 1;
    }

  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      char output_ocra[11];
      oath_ocrasuite_t *osh;
      char Q[OATH_CHALLENGE_MAXLEN];

      rc = oath_ocrasuite_parse (tv[i].ocra_suite, &osh);
      if (rc != OATH_OK)
	{
	  printf ("oath_ocrasuite_parse[%d] error %d for %s\n",
		  i, rc, tv[i].ocra_suite);
	  return 1;
	}

      rc = oath_ocra_challenge_convert (tv[i].number_of_challenges,
					tv[i].challenge_types,
					tv[i].challenge_strings, Q);
      if (memcmp (Q, tv[i].challenges_binary, OATH_CHALLENGE_MAXLEN) != 0)
	{
	  size_t j;
	  printf ("oath_ocra_challenge_convert[%d] error:\n", i);
	  for (j = 0; j < OATH_CHALLENGE_MAXLEN; j++)
	    printf ("\\%02x", Q[j]);
	  printf ("\n");
	  for (j = 0; j < OATH_CHALLENGE_MAXLEN; j++)
	    printf ("\\%02x", tv[i].challenges_binary[j]);
	  printf ("\n");
	  return 1;
	}

      rc = oath_ocra_generate (tv[i].secret, strlen (tv[i].secret),
			       osh, tv[i].counter,
			       tv[i].challenges_binary,
			       pHash, tv[i].session, tv[i].now, output_ocra);
      oath_ocrasuite_done (osh);
      if (rc != OATH_OK)
	{
	  printf ("oath_ocra_generate[%d] error %d\n", i, rc);
	  return 1;
	}

      if (strcmp (output_ocra, tv[i].ocra) != 0)
	{
	  printf ("wrong ocra value at %d: %s / %s\n",
		  i, output_ocra, tv[i].ocra);
	  return 1;
	}
    }

  rc = oath_done ();
  if (rc != OATH_OK)
    {
      printf ("oath_done: %d\n", rc);
      return 1;
    }

  return 0;
}
