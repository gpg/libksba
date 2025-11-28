/* sha1.c - SHA1 and SHA2 hash function
 * Copyright (C) 1998, 2001, 2002, 2003 Free Software Foundation, Inc.
 * Copyright (C) 2004, 2009 g10 Code GmbH
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* These are simplified SHA-1 and SHA-256 versions taken from the
 * libgrypt and gpg4win's sha1sum.c.  We need them for some tests
 * (e.g. OCSP).
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef HAVE_TYPE_U32
#undef u32	    /* maybe there is a macro with this name */
#if SIZEOF_UNSIGNED_INT == 4
    typedef unsigned int u32;
#elif SIZEOF_UNSIGNED_LONG == 4
    typedef unsigned long u32;
#else
#error no typedef for u32
#endif
#define HAVE_TYPE_U32
#endif

typedef struct
{
    u32  h0,h1,h2,h3,h4;
    u32  nblocks;
    unsigned char buf[64];
    int  count;
} sha1_context_t;

typedef struct
{
    u32  h0,h1,h2,h3,h4,h5,h6,h7;
    u32  nblocks;
    unsigned char buf[64];
    int  count;
} sha256_context_t;


#define rol(x,n) ( ((x) << (n)) | ((x) >> (32-(n))) )
#define ror(x,n) ( ((x) >> (n)) | ((x) << (32-(n))) )


static void
sha1_init (void *context)
{
  sha1_context_t *hd = context;

  hd->h0 = 0x67452301;
  hd->h1 = 0xefcdab89;
  hd->h2 = 0x98badcfe;
  hd->h3 = 0x10325476;
  hd->h4 = 0xc3d2e1f0;
  hd->nblocks = 0;
  hd->count = 0;
}

static void
sha256_init (void *context)
{
  sha256_context_t *hd = context;

  hd->h0 = 0x6a09e667;
  hd->h1 = 0xbb67ae85;
  hd->h2 = 0x3c6ef372;
  hd->h3 = 0xa54ff53a;
  hd->h4 = 0x510e527f;
  hd->h5 = 0x9b05688c;
  hd->h6 = 0x1f83d9ab;
  hd->h7 = 0x5be0cd19;

  hd->nblocks = 0;
  hd->count = 0;
}


/****************
 * Transform the message X which consists of 16 32-bit-words
 */
static void
transform (sha1_context_t *hd, unsigned char *data )
{
  register u32 a,b,c,d,e,tm;
  u32 x[16];

  /* Get values from the chaining vars. */
  a = hd->h0;
  b = hd->h1;
  c = hd->h2;
  d = hd->h3;
  e = hd->h4;

#ifdef WORDS_BIGENDIAN
  memcpy( x, data, 64 );
#else
  {
    int i;
    unsigned char *p2;
    for(i=0, p2=(unsigned char*)x; i < 16; i++, p2 += 4 )
      {
        p2[3] = *data++;
        p2[2] = *data++;
        p2[1] = *data++;
        p2[0] = *data++;
      }
  }
#endif


#define K1  0x5A827999L
#define K2  0x6ED9EBA1L
#define K3  0x8F1BBCDCL
#define K4  0xCA62C1D6L
#define F1(x,y,z)   ( z ^ ( x & ( y ^ z ) ) )
#define F2(x,y,z)   ( x ^ y ^ z )
#define F3(x,y,z)   ( ( x & y ) | ( z & ( x | y ) ) )
#define F4(x,y,z)   ( x ^ y ^ z )


#define M(i) ( tm =   x[i&0x0f] ^ x[(i-14)&0x0f] \
		    ^ x[(i-8)&0x0f] ^ x[(i-3)&0x0f] \
	       , (x[i&0x0f] = rol(tm, 1)) )

#define R(a,b,c,d,e,f,k,m)  do { e += rol( a, 5 )     \
				      + f( b, c, d )  \
				      + k	      \
				      + m;	      \
				 b = rol( b, 30 );    \
			       } while(0)
  R( a, b, c, d, e, F1, K1, x[ 0] );
  R( e, a, b, c, d, F1, K1, x[ 1] );
  R( d, e, a, b, c, F1, K1, x[ 2] );
  R( c, d, e, a, b, F1, K1, x[ 3] );
  R( b, c, d, e, a, F1, K1, x[ 4] );
  R( a, b, c, d, e, F1, K1, x[ 5] );
  R( e, a, b, c, d, F1, K1, x[ 6] );
  R( d, e, a, b, c, F1, K1, x[ 7] );
  R( c, d, e, a, b, F1, K1, x[ 8] );
  R( b, c, d, e, a, F1, K1, x[ 9] );
  R( a, b, c, d, e, F1, K1, x[10] );
  R( e, a, b, c, d, F1, K1, x[11] );
  R( d, e, a, b, c, F1, K1, x[12] );
  R( c, d, e, a, b, F1, K1, x[13] );
  R( b, c, d, e, a, F1, K1, x[14] );
  R( a, b, c, d, e, F1, K1, x[15] );
  R( e, a, b, c, d, F1, K1, M(16) );
  R( d, e, a, b, c, F1, K1, M(17) );
  R( c, d, e, a, b, F1, K1, M(18) );
  R( b, c, d, e, a, F1, K1, M(19) );
  R( a, b, c, d, e, F2, K2, M(20) );
  R( e, a, b, c, d, F2, K2, M(21) );
  R( d, e, a, b, c, F2, K2, M(22) );
  R( c, d, e, a, b, F2, K2, M(23) );
  R( b, c, d, e, a, F2, K2, M(24) );
  R( a, b, c, d, e, F2, K2, M(25) );
  R( e, a, b, c, d, F2, K2, M(26) );
  R( d, e, a, b, c, F2, K2, M(27) );
  R( c, d, e, a, b, F2, K2, M(28) );
  R( b, c, d, e, a, F2, K2, M(29) );
  R( a, b, c, d, e, F2, K2, M(30) );
  R( e, a, b, c, d, F2, K2, M(31) );
  R( d, e, a, b, c, F2, K2, M(32) );
  R( c, d, e, a, b, F2, K2, M(33) );
  R( b, c, d, e, a, F2, K2, M(34) );
  R( a, b, c, d, e, F2, K2, M(35) );
  R( e, a, b, c, d, F2, K2, M(36) );
  R( d, e, a, b, c, F2, K2, M(37) );
  R( c, d, e, a, b, F2, K2, M(38) );
  R( b, c, d, e, a, F2, K2, M(39) );
  R( a, b, c, d, e, F3, K3, M(40) );
  R( e, a, b, c, d, F3, K3, M(41) );
  R( d, e, a, b, c, F3, K3, M(42) );
  R( c, d, e, a, b, F3, K3, M(43) );
  R( b, c, d, e, a, F3, K3, M(44) );
  R( a, b, c, d, e, F3, K3, M(45) );
  R( e, a, b, c, d, F3, K3, M(46) );
  R( d, e, a, b, c, F3, K3, M(47) );
  R( c, d, e, a, b, F3, K3, M(48) );
  R( b, c, d, e, a, F3, K3, M(49) );
  R( a, b, c, d, e, F3, K3, M(50) );
  R( e, a, b, c, d, F3, K3, M(51) );
  R( d, e, a, b, c, F3, K3, M(52) );
  R( c, d, e, a, b, F3, K3, M(53) );
  R( b, c, d, e, a, F3, K3, M(54) );
  R( a, b, c, d, e, F3, K3, M(55) );
  R( e, a, b, c, d, F3, K3, M(56) );
  R( d, e, a, b, c, F3, K3, M(57) );
  R( c, d, e, a, b, F3, K3, M(58) );
  R( b, c, d, e, a, F3, K3, M(59) );
  R( a, b, c, d, e, F4, K4, M(60) );
  R( e, a, b, c, d, F4, K4, M(61) );
  R( d, e, a, b, c, F4, K4, M(62) );
  R( c, d, e, a, b, F4, K4, M(63) );
  R( b, c, d, e, a, F4, K4, M(64) );
  R( a, b, c, d, e, F4, K4, M(65) );
  R( e, a, b, c, d, F4, K4, M(66) );
  R( d, e, a, b, c, F4, K4, M(67) );
  R( c, d, e, a, b, F4, K4, M(68) );
  R( b, c, d, e, a, F4, K4, M(69) );
  R( a, b, c, d, e, F4, K4, M(70) );
  R( e, a, b, c, d, F4, K4, M(71) );
  R( d, e, a, b, c, F4, K4, M(72) );
  R( c, d, e, a, b, F4, K4, M(73) );
  R( b, c, d, e, a, F4, K4, M(74) );
  R( a, b, c, d, e, F4, K4, M(75) );
  R( e, a, b, c, d, F4, K4, M(76) );
  R( d, e, a, b, c, F4, K4, M(77) );
  R( c, d, e, a, b, F4, K4, M(78) );
  R( b, c, d, e, a, F4, K4, M(79) );

  /* Update chaining vars. */
  hd->h0 += a;
  hd->h1 += b;
  hd->h2 += c;
  hd->h3 += d;
  hd->h4 += e;

#undef R
#undef M
#undef F1
#undef F2
#undef F3
#undef F4
#undef K1
#undef K2
#undef K3
#undef K4
}


# define Cho(x,y,z) (z ^ (x & (y ^ z)))      /* (4.2) same as SHA-1's F1 */
# define Maj(x,y,z) ((x & y) | (z & (x|y)))  /* (4.3) same as SHA-1's F3 */
# define Sum0(x) (ror ((x), 2) ^ ror ((x), 13) ^ ror ((x), 22))  /* (4.4) */
# define Sum1(x) (ror ((x), 6) ^ ror ((x), 11) ^ ror ((x), 25))  /* (4.5) */
# define S0(x) (ror ((x), 7) ^ ror ((x), 18) ^ ((x) >> 3))       /* (4.6) */
# define S1(x) (ror ((x), 17) ^ ror ((x), 19) ^ ((x) >> 10))     /* (4.7) */
# define R(a,b,c,d,e,f,g,h,k,w) do                                \
           {                                                      \
            t1 = (h) + Sum1((e)) + Cho((e),(f),(g)) + (k) + (w);  \
            t2 = Sum0((a)) + Maj((a),(b),(c));                    \
            h = g;                                                \
            g = f;                                                \
            f = e;                                                \
            e = d + t1;                                           \
            d = c;                                                \
            c = b;                                                \
            b = a;                                                \
            a = t1 + t2;                                          \
          } while (0)

static void
transform256 (sha256_context_t *hd, unsigned char *data)
{
  static const u32 K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };
  u32 a,b,c,d,e,f,g,h,t1,t2;
  u32 x[16];
  u32 w[64];
  int i;
  a = hd->h0;
  b = hd->h1;
  c = hd->h2;
  d = hd->h3;
  e = hd->h4;
  f = hd->h5;
  g = hd->h6;
  h = hd->h7;

#ifdef WORDS_BIGENDIAN
    memcpy (x, data, 64);
#else
    {
      unsigned char *p2;

      for (i=0, p2=(unsigned char*)x; i < 16; i++, p2 += 4 )
        {
          p2[3] = *data++;
          p2[2] = *data++;
          p2[1] = *data++;
          p2[0] = *data++;
        }
    }
#endif

  for (i=0; i < 16; i++)
    w[i] = x[i];
  for (; i < 64; i++)
    w[i] = S1(w[i-2]) + w[i-7] + S0(w[i-15]) + w[i-16];

  for (i=0; i < 64; i++)
    R(a,b,c,d,e,f,g,h,K[i],w[i]);

  hd->h0 += a;
  hd->h1 += b;
  hd->h2 += c;
  hd->h3 += d;
  hd->h4 += e;
  hd->h5 += f;
  hd->h6 += g;
  hd->h7 += h;
}
# undef Cho
# undef Maj
# undef Sum0
# undef Sum1
# undef S0
# undef S1
# undef R



/* Update the message digest with the contents
 * of INBUF with length INLEN.
 */
static void
sha1_write( void *context, unsigned char *inbuf, size_t inlen)
{
  sha1_context_t *hd = context;

  if( hd->count == 64 )  /* flush the buffer */
    {
      transform( hd, hd->buf );
      hd->count = 0;
      hd->nblocks++;
    }
  if( !inbuf )
    return;

  if( hd->count )
    {
      for( ; inlen && hd->count < 64; inlen-- )
        hd->buf[hd->count++] = *inbuf++;
      sha1_write( hd, NULL, 0 );
      if( !inlen )
        return;
    }

  while( inlen >= 64 )
    {
      transform( hd, inbuf );
      hd->count = 0;
      hd->nblocks++;
      inlen -= 64;
      inbuf += 64;
    }
  for( ; inlen && hd->count < 64; inlen-- )
    hd->buf[hd->count++] = *inbuf++;
}


/* Update the message digest with the contents
 * of INBUF with length INLEN.
 */
static void
sha256_write (void *context, unsigned char *inbuf, size_t inlen)
{
  sha256_context_t *hd = context;

  if( hd->count == 64 )  /* flush the buffer */
    {
      transform256( hd, hd->buf );
      hd->count = 0;
      hd->nblocks++;
    }
  if( !inbuf )
    return;

  if( hd->count )
    {
      for( ; inlen && hd->count < 64; inlen-- )
        hd->buf[hd->count++] = *inbuf++;
      sha256_write( hd, NULL, 0 );
      if( !inlen )
        return;
    }

  while( inlen >= 64 )
    {
      transform256( hd, inbuf );
      hd->count = 0;
      hd->nblocks++;
      inlen -= 64;
      inbuf += 64;
    }
  for( ; inlen && hd->count < 64; inlen-- )
    hd->buf[hd->count++] = *inbuf++;
}


/* The routine final terminates the computation and
 * returns the digest.
 * The handle is prepared for a new cycle, but adding bytes to the
 * handle will the destroy the returned buffer.
 * Returns: 20 bytes representing the digest.
 */

static void
sha1_final(void *context)
{
  sha1_context_t *hd = context;

  u32 t, msb, lsb;
  unsigned char *p;

  sha1_write(hd, NULL, 0); /* flush */;

  t = hd->nblocks;
  /* multiply by 64 to make a byte count */
  lsb = t << 6;
  msb = t >> 26;
  /* add the count */
  t = lsb;
  if( (lsb += hd->count) < t )
    msb++;
  /* multiply by 8 to make a bit count */
  t = lsb;
  lsb <<= 3;
  msb <<= 3;
  msb |= t >> 29;

  if( hd->count < 56 )  /* enough room */
    {
      hd->buf[hd->count++] = 0x80; /* pad */
      while( hd->count < 56 )
        hd->buf[hd->count++] = 0;  /* pad */
    }
  else  /* need one extra block */
    {
      hd->buf[hd->count++] = 0x80; /* pad character */
      while( hd->count < 64 )
        hd->buf[hd->count++] = 0;
      sha1_write(hd, NULL, 0);  /* flush */;
      memset(hd->buf, 0, 56 ); /* fill next block with zeroes */
    }
  /* append the 64 bit count */
  hd->buf[56] = msb >> 24;
  hd->buf[57] = msb >> 16;
  hd->buf[58] = msb >>  8;
  hd->buf[59] = msb	   ;
  hd->buf[60] = lsb >> 24;
  hd->buf[61] = lsb >> 16;
  hd->buf[62] = lsb >>  8;
  hd->buf[63] = lsb	   ;
  transform( hd, hd->buf );

  p = hd->buf;
#ifdef WORDS_BIGENDIAN
#define X(a) do { *(u32*)p = hd->h##a ; p += 4; } while(0)
#else /* little endian */
#define X(a) do { *p++ = hd->h##a >> 24; *p++ = hd->h##a >> 16;	 \
                  *p++ = hd->h##a >> 8; *p++ = hd->h##a; } while(0)
#endif
  X(0);
  X(1);
  X(2);
  X(3);
  X(4);
#undef X

}

static void
sha256_final(void *context)
{
  sha256_context_t *hd = context;

  u32 t, msb, lsb;
  unsigned char *p;

  sha256_write(hd, NULL, 0); /* flush */;

  t = hd->nblocks;
  /* multiply by 64 to make a byte count */
  lsb = t << 6;
  msb = t >> 26;
  /* add the count */
  t = lsb;
  if( (lsb += hd->count) < t )
    msb++;
  /* multiply by 8 to make a bit count */
  t = lsb;
  lsb <<= 3;
  msb <<= 3;
  msb |= t >> 29;

  if( hd->count < 56 )  /* enough room */
    {
      hd->buf[hd->count++] = 0x80; /* pad */
      while( hd->count < 56 )
        hd->buf[hd->count++] = 0;  /* pad */
    }
  else  /* need one extra block */
    {
      hd->buf[hd->count++] = 0x80; /* pad character */
      while( hd->count < 64 )
        hd->buf[hd->count++] = 0;
      sha256_write(hd, NULL, 0);  /* flush */;
      memset(hd->buf, 0, 56 ); /* fill next block with zeroes */
    }
  /* append the 64 bit count */
  hd->buf[56] = msb >> 24;
  hd->buf[57] = msb >> 16;
  hd->buf[58] = msb >>  8;
  hd->buf[59] = msb	   ;
  hd->buf[60] = lsb >> 24;
  hd->buf[61] = lsb >> 16;
  hd->buf[62] = lsb >>  8;
  hd->buf[63] = lsb	   ;
  transform256( hd, hd->buf );

  p = hd->buf;
#ifdef WORDS_BIGENDIAN
#define X(a) do { *(u32*)p = hd->h##a ; p += 4; } while(0)
#else /* little endian */
#define X(a) do { *p++ = hd->h##a >> 24; *p++ = hd->h##a >> 16;	 \
                  *p++ = hd->h##a >> 8; *p++ = hd->h##a; } while(0)
#endif
  X(0);
  X(1);
  X(2);
  X(3);
  X(4);
  X(5);
  X(6);
  X(7);
#undef X
}


void
sha1_hash_buffer (char *outbuf, const char *buffer, size_t length)
{
  sha1_context_t hd;

  sha1_init (&hd);
  sha1_write (&hd, (unsigned char *)buffer, length);
  sha1_final (&hd);
  memcpy (outbuf, hd.buf, 20);
}


void
sha256_hash_buffer (char *outbuf, const char *buffer, size_t length)
{
  static int selftest;
  sha256_context_t hd;

  if (!selftest)
    {
      unsigned char result[32];
      selftest = 1;

      sha256_hash_buffer (result, "abc", 3);
      if (memcmp
          (result,
           "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
           "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad",
           32))
        {
          fputs ("fatal: internal SHA256 selftest failed\n", stderr);
          exit (8);
        }
    }

  sha256_init (&hd);
  sha256_write (&hd, (unsigned char *)buffer, length);
  sha256_final (&hd);
  memcpy (outbuf, hd.buf, 32);
}
