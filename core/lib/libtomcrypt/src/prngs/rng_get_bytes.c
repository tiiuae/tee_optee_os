// SPDX-License-Identifier: BSD-2-Clause
/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

#ifdef LTC_RNG_GET_BYTES
/**
   @file rng_get_bytes.c
   portable way to get secure random bits to feed a PRNG (Tom St Denis)
*/

static unsigned long long riscv_clock(void)
{
   unsigned long long n;
   asm volatile(
        "rdtime %0"
        : "=r"(n));
   return (n/10);
}

#define SEL4CLOCK riscv_clock


#if defined(LTC_DEVRANDOM) && !defined(_WIN32)
/* on *NIX read /dev/random */
static unsigned long _rng_nix(unsigned char *buf, unsigned long len,
                             void (*callback)(void))
{
#ifdef LTC_NO_FILE
    LTC_UNUSED_PARAM(callback);
    LTC_UNUSED_PARAM(buf);
    LTC_UNUSED_PARAM(len);
    return 0;
#else
    FILE *f;
    unsigned long x;
    LTC_UNUSED_PARAM(callback);
#ifdef LTC_TRY_URANDOM_FIRST
    f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
       f = fopen("/dev/random", "rb");
    }
#else
    f = fopen("/dev/random", "rb");
#endif /* LTC_TRY_URANDOM_FIRST */

    if (f == NULL) {
       return 0;
    }

    /* disable buffering */
    if (setvbuf(f, NULL, _IONBF, 0) != 0) {
       fclose(f);
       return 0;
    }

    x = (unsigned long)fread(buf, 1, (size_t)len, f);
    fclose(f);
    return x;
#endif /* LTC_NO_FILE */
}

#endif /* LTC_DEVRANDOM */

#if !defined(_WIN32_WCE)

#define ANSI_RNG

static unsigned long _rng_ansic(unsigned char *buf, unsigned long len,
                               void (*callback)(void))
{
   volatile unsigned long long t1;
   int l, acc, bits, a, b;
   l = len;
   bits = 8;
   acc  = a = b = 0;
   while (len--) {
       if (callback != NULL) callback();
       while (bits--) {
          do {
             t1 = SEL4CLOCK();
            
             do {
                 a ^= 1;
             } while (t1 == SEL4CLOCK());
             t1 = SEL4CLOCK();
             do {
                 b ^= 1;
             } while (t1 == SEL4CLOCK());
          } while (a == b);
          acc = (acc << 1) | a;
       }
       *buf++ = acc;
       acc  = 0;
       bits = 8;
   }
   return l;
}

#endif

/* Try the Microsoft CSP */
#if defined(_WIN32) || defined(_WIN32_WCE)
#ifndef _WIN32_WINNT
  #define _WIN32_WINNT 0x0400
#endif
#ifdef _WIN32_WCE
   #define UNDER_CE
   #define ARM
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

static unsigned long _rng_win32(unsigned char *buf, unsigned long len,
                               void (*callback)(void))
{
   HCRYPTPROV hProv = 0;
   LTC_UNUSED_PARAM(callback);
   if (!CryptAcquireContext(&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL,
                            (CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET)) &&
       !CryptAcquireContext (&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET))
      return 0;

   if (CryptGenRandom(hProv, len, buf) == TRUE) {
      CryptReleaseContext(hProv, 0);
      return len;
   } else {
      CryptReleaseContext(hProv, 0);
      return 0;
   }
}

#endif /* WIN32 */

/**
  Read the system RNG
  @param out       Destination
  @param outlen    Length desired (octets)
  @param callback  Pointer to void function to act as "callback" when RNG is slow.  This can be NULL
  @return Number of octets read
*/
unsigned long rng_get_bytes(unsigned char *out, unsigned long outlen,
                            void (*callback)(void))
{
   unsigned long x;

   LTC_ARGCHK(out != NULL);

#ifdef LTC_PRNG_ENABLE_LTC_RNG
   if (ltc_rng) {
      x = ltc_rng(out, outlen, callback);
      if (x != 0) {
         return x;
      }
   }
#endif

#if defined(_WIN32) || defined(_WIN32_WCE)
   x = _rng_win32(out, outlen, callback); if (x != 0) { return x; }
#elif defined(LTC_DEVRANDOM)
   x = _rng_nix(out, outlen, callback);   if (x != 0) { return x; }
#endif
#ifdef ANSI_RNG
   x = _rng_ansic(out, outlen, callback); if (x != 0) { return x; }
#endif
   return 0;
}
#endif /* #ifdef LTC_RNG_GET_BYTES */

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
