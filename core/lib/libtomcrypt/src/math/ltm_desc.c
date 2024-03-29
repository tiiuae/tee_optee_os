// SPDX-License-Identifier: BSD-2-Clause
/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#define DESC_DEF_ONLY
#include "tomcrypt_private.h"

#ifdef LTM_DESC

#include <tommath.h>

static const struct {
    int mpi_code, ltc_code;
} mpi_to_ltc_codes[] = {
   { MP_OKAY ,  CRYPT_OK},
   { MP_MEM  ,  CRYPT_MEM},
   { MP_VAL  ,  CRYPT_INVALID_ARG},
};

/**
   Convert a MPI error to a LTC error (Possibly the most powerful function ever!  Oh wait... no)
   @param err    The error to convert
   @return The equivalent LTC error code or CRYPT_ERROR if none found
*/
static int mpi_to_ltc_error(int err)
{
   int x;

   for (x = 0; x < (int)(sizeof(mpi_to_ltc_codes)/sizeof(mpi_to_ltc_codes[0])); x++) {
       if (err == mpi_to_ltc_codes[x].mpi_code) {
          return mpi_to_ltc_codes[x].ltc_code;
       }
   }
   return CRYPT_ERROR;
}

static int init(void **a)
{
   int err;

   LTC_ARGCHK(a != NULL);

   *a = XCALLOC(1, sizeof(mp_int));
   if (*a == NULL) {
      return CRYPT_MEM;
   }

   if ((err = mpi_to_ltc_error(mp_init(*a))) != CRYPT_OK) {
      XFREE(*a);
   }
   return err;
}

static int init_size(int size_bits, void **a)
{
   int err;
   LTC_ARGCHK(a != NULL);

   *a = XCALLOC(1, sizeof(mp_int));
   if (*a == NULL) {
      return CRYPT_MEM;
   }

   if ((err = mpi_to_ltc_error(mp_init_size(*a, size_bits))) != CRYPT_OK) {
      XFREE(*a);
   }
   return err;
}

static void deinit(void *a)
{
   LTC_ARGCHKVD(a != NULL);
   mp_clear(a);
   XFREE(a);
}

static int neg(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_neg(a, b));
}

static int copy(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_copy(a, b));
}

static int init_copy(void **a, void *b)
{
   if (init(a) != CRYPT_OK) {
      return CRYPT_MEM;
   }
   return copy(b, *a);
}

/* ---- trivial ---- */
static int set_int(void *a, ltc_mp_digit b)
{
   LTC_ARGCHK(a != NULL);
#ifdef BN_MP_SET_INT_C
   return mpi_to_ltc_error(mp_set_int(a, b));
#else
   mp_set_u32(a, b);
   return CRYPT_OK;
#endif
}

static unsigned long get_int(void *a)
{
   LTC_ARGCHK(a != NULL);
#ifdef BN_MP_GET_INT_C
   return mp_get_int(a);
#else
   return mp_get_ul(a);
#endif
}

static ltc_mp_digit get_digit(void *a, int n)
{
   mp_int *A;
   LTC_ARGCHK(a != NULL);
   A = a;
   return (n >= A->used || n < 0) ? 0 : A->dp[n];
}

static int get_digit_count(void *a)
{
   mp_int *A;
   LTC_ARGCHK(a != NULL);
   A = a;
   return A->used;
}

static int compare(void *a, void *b)
{
   int ret;
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   ret = mp_cmp(a, b);
   switch (ret) {
      case MP_LT: return LTC_MP_LT;
      case MP_EQ: return LTC_MP_EQ;
      case MP_GT: return LTC_MP_GT;
      default:    return 0;
   }
}

static int compare_d(void *a, ltc_mp_digit b)
{
   int ret;
   LTC_ARGCHK(a != NULL);
   ret = mp_cmp_d(a, b);
   switch (ret) {
      case MP_LT: return LTC_MP_LT;
      case MP_EQ: return LTC_MP_EQ;
      case MP_GT: return LTC_MP_GT;
      default:    return 0;
   }
}

static int count_bits(void *a)
{
   LTC_ARGCHK(a != NULL);
   return mp_count_bits(a);
}

static int count_lsb_bits(void *a)
{
   LTC_ARGCHK(a != NULL);
   return mp_cnt_lsb(a);
}


static int twoexpt(void *a, int n)
{
   LTC_ARGCHK(a != NULL);
   return mpi_to_ltc_error(mp_2expt(a, n));
}

/* ---- conversions ---- */

/* read ascii string */
static int read_radix(void *a, const char *b, int radix)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_read_radix(a, b, radix));
}

/* write one */
static int write_radix(void *a, char *b, int radix)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_to_hex(a, b, radix));
}

/* get size as unsigned char string */
static unsigned long unsigned_size(void *a)
{
   LTC_ARGCHK(a != NULL);
   return mp_ubin_size(a);
}

/* store */
static int unsigned_write(void *a, unsigned char *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   size_t maxlen = SIZE_MAX;
   size_t written = 0;

   return mpi_to_ltc_error(mp_to_ubin(a, b, maxlen, &written));
}

/* read */
static int unsigned_read(void *a, unsigned char *b, unsigned long len)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_from_ubin(a, b, len));
}

/* add */
static int add(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_add(a, b, c));
}

static int addi(void *a, ltc_mp_digit b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_add_d(a, b, c));
}

/* sub */
static int sub(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_sub(a, b, c));
}

static int subi(void *a, ltc_mp_digit b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_sub_d(a, b, c));
}

/* mul */
static int mul(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_mul(a, b, c));
}

static int muli(void *a, ltc_mp_digit b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_mul_d(a, b, c));
}

/* sqr */
static int sqr(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_sqr(a, b));
}

/* sqrtmod_prime */
static int sqrtmod_prime(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_sqrtmod_prime(a, b, c));
}

/* div */
static int divide(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_div(a, b, c, d));
}

static int div_2(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_div_2(a, b));
}

/* modi */
static int modi(void *a, ltc_mp_digit b, ltc_mp_digit *c)
{
   mp_digit tmp;
   int      err;

   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);

   if ((err = mpi_to_ltc_error(mp_mod_d(a, b, &tmp))) != CRYPT_OK) {
      return err;
   }
   *c = tmp;
   return CRYPT_OK;
}

/* gcd */
static int gcd(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_gcd(a, b, c));
}

/* lcm */
static int lcm(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_lcm(a, b, c));
}

static int addmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   return mpi_to_ltc_error(mp_addmod(a,b,c,d));
}

static int submod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   return mpi_to_ltc_error(mp_submod(a,b,c,d));
}

static int mulmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   return mpi_to_ltc_error(mp_mulmod(a,b,c,d));
}

static int sqrmod(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_sqrmod(a,b,c));
}

/* invmod */
static int invmod(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_invmod(a, b, c));
}

/* setup */
static int montgomery_setup(void *a, void **b)
{
   int err;
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   *b = XCALLOC(1, sizeof(mp_digit));
   if (*b == NULL) {
      return CRYPT_MEM;
   }
   if ((err = mpi_to_ltc_error(mp_montgomery_setup(a, (mp_digit *)*b))) != CRYPT_OK) {
      XFREE(*b);
   }
   return err;
}

/* get normalization value */
static int montgomery_normalization(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   return mpi_to_ltc_error(mp_montgomery_calc_normalization(a, b));
}

/* reduce */
static int montgomery_reduce(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   return mpi_to_ltc_error(mp_montgomery_reduce(a, b, *((mp_digit *)c)));
}

/* clean up */
static void montgomery_deinit(void *a)
{
   XFREE(a);
}

static int exptmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   return mpi_to_ltc_error(mp_exptmod(a,b,c,d));
}

static int isprime(void *a, int b, int *c)
{
   int err;
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   b = mp_prime_rabin_miller_trials(mp_count_bits(a));
   err = mpi_to_ltc_error(mp_prime_is_prime(a, b, (bool*)c));
   *c = (*c == MP_YES) ? LTC_MP_YES : LTC_MP_NO;
   return err;
}

static int set_rand(void *a, int size)
{
   LTC_ARGCHK(a != NULL);
   return mpi_to_ltc_error(mp_rand(a, size));
}

#ifndef MP_DIGIT_BIT
#define MP_DIGIT_BIT DIGIT_BIT
#endif

const ltc_math_descriptor ltm_desc = {

   .name ="LibTomMath",
   .bits_per_digit = (int)MP_DIGIT_BIT,

   .init = init,
   .init_copy = init_copy,
   .init_size = init_size,
   .deinit = deinit,

   .neg = neg,
   .copy = copy,

   .set_int = set_int,
   .get_int = get_int,
   .get_digit = get_digit,
   .get_digit_count = get_digit_count,
   .compare = compare,
   .compare_d = compare_d,
   .count_bits = count_bits,
   .count_lsb_bits = count_lsb_bits,
   .twoexpt = twoexpt,

   .read_radix = read_radix,
	.write_radix = write_radix,
	.unsigned_size = unsigned_size,
	.unsigned_write = unsigned_write,
	.unsigned_read = unsigned_read,

	.add = add,
	.addi = addi,
	.sub = sub,
	.subi = subi,
	.mul = mul,
	.muli = muli,
	.sqr = sqr,
	.mpdiv = divide,
	.div_2 = div_2,
	.modi = modi,
	.gcd = gcd,
	.lcm = lcm,

	.mulmod = mulmod,
	.sqrmod = sqrmod,
	.invmod = invmod,

	.montgomery_setup = montgomery_setup,
	.montgomery_normalization = montgomery_normalization,
	.montgomery_reduce = montgomery_reduce,
	.montgomery_deinit = montgomery_deinit,

	.exptmod = exptmod,
	.isprime = isprime,

#ifdef LTC_MECC
#ifdef LTC_MECC_FP
	.ecc_ptmul = ltc_ecc_fp_mulmod,
#else
	.ecc_ptmul = ltc_ecc_mulmod,
#endif /* LTC_MECC_FP */
	.ecc_ptadd = ltc_ecc_projective_add_point,
	.ecc_ptdbl = ltc_ecc_projective_dbl_point,
	.ecc_map = ltc_ecc_map,
#ifdef LTC_ECC_SHAMIR
#ifdef LTC_MECC_FP
	.ecc_mul2add = ltc_ecc_fp_mul2add,
#else
	.ecc_mul2add = ltc_ecc_mul2add,
#endif /* LTC_MECC_FP */
#endif /* LTC_ECC_SHAMIR */
#endif /* LTC_MECC */

#ifdef LTC_MRSA
	.rsa_keygen = rsa_make_key,
	.rsa_me = rsa_exptmod,
#endif
	.addmod = addmod,
	.submod = submod,

   .rand = set_rand,

};


#endif

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
