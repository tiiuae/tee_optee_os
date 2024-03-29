// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <config.h>
#include <crypto/crypto_impl.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>
#include <utee_defines.h>
#include "acipher_helpers.h"

extern prng_state sel4_prng;

static void _ltc_ecc_free_public_key(struct ecc_public_key *s)
{
	if (!s)
		return;

	crypto_bignum_free(s->x);
	crypto_bignum_free(s->y);
}

void ecc_free_keypair(struct ecc_keypair *s)
{
	if (!s)
		return;
	crypto_bignum_free(s->y);
	crypto_bignum_free(s->d);
	crypto_bignum_free(s->x);
}

/*
 * For a given TEE @curve, return key size and LTC curve name. Also check that
 * @algo is compatible with this curve.
 * @curve: TEE_ECC_CURVE_NIST_P192, ...
 * @algo: TEE_ALG_ECDSA_P192, ...
 */
static TEE_Result ecc_get_curve_info(uint32_t curve, uint32_t algo,
				     size_t *key_size_bytes,
				     size_t *key_size_bits,
				     const char **curve_name)
{
	size_t size_bytes = 0;
	size_t size_bits = 0;
	const char *name = NULL;

	/*
	 * Excerpt of libtomcrypt documentation:
	 * ecc_make_key(... key_size ...): The keysize is the size of the
	 * modulus in bytes desired. Currently directly supported values
	 * are 12, 16, 20, 24, 28, 32, 48, and 65 bytes which correspond
	 * to key sizes of 112, 128, 160, 192, 224, 256, 384, and 521 bits
	 * respectively.
	 */

	/*
	 * Note GPv1.1 indicates TEE_ALG_ECDH_NIST_P192_DERIVE_SHARED_SECRET
	 * but defines TEE_ALG_ECDH_P192
	 */

	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		size_bits = 192;
		size_bytes = 24;
		name = "NISTP192";
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P192) &&
		    (algo != TEE_ALG_ECDH_P192))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P224:
		size_bits = 224;
		size_bytes = 28;
		name = "NISTP224";
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P224) &&
		    (algo != TEE_ALG_ECDH_P224))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P256:
		size_bits = 256;
		size_bytes = 32;
		name = "NISTP256";
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P256) &&
		    (algo != TEE_ALG_ECDH_P256))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P384:
		size_bits = 384;
		size_bytes = 48;
		name = "NISTP384";
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P384) &&
		    (algo != TEE_ALG_ECDH_P384))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		size_bits = 521;
		size_bytes = 66;
		name = "NISTP521";
		if ((algo != 0) && (algo != TEE_ALG_ECDSA_P521) &&
		    (algo != TEE_ALG_ECDH_P521))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	case TEE_ECC_CURVE_SM2:
		size_bits = 256;
		size_bytes = 32;
		name = "SM2";
		if ((algo != 0) && (algo != TEE_ALG_SM2_PKE) &&
		    (algo != TEE_ALG_SM2_DSA_SM3) &&
		    (algo != TEE_ALG_SM2_KEP))
			return TEE_ERROR_BAD_PARAMETERS;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (key_size_bytes)
		*key_size_bytes = size_bytes;
	if (key_size_bits)
		*key_size_bits = size_bits;
	if (curve_name)
		*curve_name = name;
	return TEE_SUCCESS;
}

static TEE_Result _ltc_ecc_generate_keypair(struct ecc_keypair *key,
					    size_t key_size)
{
	TEE_Result res;
	ecc_key ltc_tmp_key;
	int ltc_res;
	size_t key_size_bytes = 0;
	size_t key_size_bits = 0;

	res = ecc_get_curve_info(key->curve, 0, &key_size_bytes, &key_size_bits,
				 NULL);
	if (res != TEE_SUCCESS)
		return res;

	if (key_size != key_size_bits)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Generate the ECC key */
	ltc_res = ecc_make_key(&sel4_prng, find_prng("fortuna"),
			       key_size_bytes, &ltc_tmp_key);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_PARAMETERS;

	/* check the size of the keys */
	if (((size_t)mp_count_bits(ltc_tmp_key.pubkey.x) > key_size_bits) ||
	    ((size_t)mp_count_bits(ltc_tmp_key.pubkey.y) > key_size_bits) ||
	    ((size_t)mp_count_bits(ltc_tmp_key.k) > key_size_bits)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/* check LTC is returning z==1 */
	if (mp_count_bits(ltc_tmp_key.pubkey.z) != 1) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	/* Copy the key */
	ltc_mp.copy(ltc_tmp_key.k, key->d);
	ltc_mp.copy(ltc_tmp_key.pubkey.x, key->x);
	ltc_mp.copy(ltc_tmp_key.pubkey.y, key->y);

	res = TEE_SUCCESS;

exit:
	ecc_free(&ltc_tmp_key);		/* Free the temporary key */
	return res;
}

/* Note: this function clears the key before setting the curve */
static TEE_Result ecc_set_curve_from_name(ecc_key *ltc_key,
					  const char *curve_name)
{
	const ltc_ecc_curve *curve = NULL;
	int ltc_res = 0;

	ltc_res = ecc_find_curve(curve_name, &curve);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_NOT_SUPPORTED;

	ltc_res = ecc_set_curve(curve, ltc_key);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

/*
 * Given a keypair "key", populate the Libtomcrypt private key "ltc_key"
 * It also returns the key size, in bytes
 */
TEE_Result ecc_populate_ltc_private_key(ecc_key *ltc_key,
					struct ecc_keypair *key,
					uint32_t algo, size_t *key_size_bytes)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const char *name = NULL;

	res = ecc_get_curve_info(key->curve, algo, key_size_bytes, NULL, &name);
	if (res)
		return res;

	memset(ltc_key, 0, sizeof(*ltc_key));

	res = ecc_set_curve_from_name(ltc_key, name);
	if (res)
		return res;

	ltc_key->type = PK_PRIVATE;
	mp_copy(key->d, ltc_key->k);
	mp_copy(key->x, ltc_key->pubkey.x);
	mp_copy(key->y, ltc_key->pubkey.y);
	mp_set_int(ltc_key->pubkey.z, 1);

	return TEE_SUCCESS;
}


TEE_Result ecc_export_keys(struct ecc_keypair *key,
								  uint8_t *priv_key,
								  size_t *priv_key_length,
								  uint8_t *public_key,
								  size_t *pub_key_length)
{
	ecc_key ltc_key;
	size_t length;
	TEE_Result ret = -1;
	const char *name = NULL;
	uint8_t one[1] = { 1 };

	if (priv_key) {
		memset(&ltc_key, 0, sizeof(ltc_key));
		ret = ecc_populate_ltc_private_key(&ltc_key, key, 0, &length);
		if (ret)
			return ret;

		ret = ecc_export(priv_key, priv_key_length, PK_PRIVATE, &ltc_key);
		if (ret)
			return ret;

	}
	if (public_key) {
		memset(&ltc_key, 0, sizeof(ltc_key));
		ret = ecc_get_curve_info(key->curve, 0, &length, NULL, &name);
		if (ret)
			return ret;
		ret = ecc_set_curve_from_name(&ltc_key, name);
		if (ret)
			return ret;

		ltc_key.type = PK_PUBLIC;
		mp_copy(key->x, ltc_key.pubkey.x);
		mp_copy(key->y, ltc_key.pubkey.y);
		mp_read_unsigned_bin(ltc_key.pubkey.z, one, sizeof(one));

		ret = ecc_export(public_key, pub_key_length, PK_PUBLIC, &ltc_key);
	}
	return ret;

}

static int set_ecc_curve_by_size(int size, uint32_t *curve)
{
   *curve = 0;

	if (size <= 24) {
		*curve = TEE_ECC_CURVE_NIST_P192;
	}
	else if (size <= 28) {
		*curve = TEE_ECC_CURVE_NIST_P224;
	}
	else if (size <= 32) {
		*curve = TEE_ECC_CURVE_NIST_P256;
	}
	else if (size <= 48) {
		*curve = TEE_ECC_CURVE_NIST_P384;
	}
	else if (size <= 66) {
		*curve = TEE_ECC_CURVE_NIST_P521;
	}

	if (!*curve)
		return -1;

	return 0;
}

TEE_Result ecc_import_keys(struct ecc_keypair *key, uint8_t *keyarray, size_t len)
{
	ecc_key ltc_tmp_key;
	TEE_Result ret = -1;

	int key_size;

	ret = ecc_import(keyarray, len, &ltc_tmp_key);
	if (ret) {
		printf("ECC import failed %d\n", ret);
		goto err;
	}

	key_size = ecc_get_size(&ltc_tmp_key);

	ret = set_ecc_curve_by_size(key_size, &key->curve);
	if (ret)
		goto err;

	if (!bn_alloc_max(&key->d))
		goto err;
	if (!bn_alloc_max(&key->x))
		goto err;
	if (!bn_alloc_max(&key->y))
		goto err;

	/* Copy the key */
	ltc_mp.copy(ltc_tmp_key.k, key->d);
	ltc_mp.copy(ltc_tmp_key.pubkey.x, key->x);
	ltc_mp.copy(ltc_tmp_key.pubkey.y, key->y);
err:
	return ret;
}

/*
 * Given a public "key", populate the Libtomcrypt public key "ltc_key"
 * It also returns the key size, in bytes
 */
TEE_Result ecc_populate_ltc_public_key(ecc_key *ltc_key,
				       struct ecc_public_key *key,
				       uint32_t algo, size_t *key_size_bytes)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const char *name = NULL;
	uint8_t one[1] = { 1 };

	res = ecc_get_curve_info(key->curve, algo, key_size_bytes, NULL, &name);
	if (res)
		return res;

	memset(ltc_key, 0, sizeof(*ltc_key));

	res = ecc_set_curve_from_name(ltc_key, name);
	if (res)
		return res;

	ltc_key->type = PK_PUBLIC;

	mp_copy(key->x, ltc_key->pubkey.x);
	mp_copy(key->y, ltc_key->pubkey.y);
	mp_read_unsigned_bin(ltc_key->pubkey.z, one, sizeof(one));

	return TEE_SUCCESS;
}

static TEE_Result _ltc_ecc_sign(uint32_t algo, struct ecc_keypair *key,
				const uint8_t *msg, size_t msg_len,
				uint8_t *sig, size_t *sig_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int ltc_res = 0;
	size_t key_size_bytes = 0;
	ecc_key ltc_key = { };
	unsigned long ltc_sig_len = 0;

	if (algo == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	res = ecc_populate_ltc_private_key(&ltc_key, key, algo,
					   &key_size_bytes);
	if (res != TEE_SUCCESS)
		return res;

	if (*sig_len < 2 * key_size_bytes) {
		*sig_len = 2 * key_size_bytes;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	ltc_sig_len = *sig_len;
	ltc_res = ecc_sign_hash_rfc7518(msg, msg_len, sig, &ltc_sig_len,
				    &sel4_prng, find_prng("fortuna"), &ltc_key);
	if (ltc_res == CRYPT_OK) {
		res = TEE_SUCCESS;
	} else {
		res = TEE_ERROR_GENERIC;
	}
	*sig_len = ltc_sig_len;

out:
	ecc_free(&ltc_key);
	return res;
}

static TEE_Result _ltc_ecc_verify(uint32_t algo, struct ecc_public_key *key,
				  const uint8_t *msg, size_t msg_len,
				  const uint8_t *sig, size_t sig_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int ltc_stat = 0;
	int ltc_res = 0;
	size_t key_size_bytes = 0;
	ecc_key ltc_key = { };

	if (algo == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	res = ecc_populate_ltc_public_key(&ltc_key, key, algo, &key_size_bytes);
	if (res != TEE_SUCCESS)
		goto out;

	/* check keysize vs sig_len */
	if ((key_size_bytes * 2) != sig_len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	ltc_res = ecc_verify_hash_rfc7518(sig, sig_len, msg, msg_len, &ltc_stat,
					  &ltc_key);
	res = convert_ltc_verify_status(ltc_res, ltc_stat);
out:
	ecc_free(&ltc_key);
	return res;
}

static TEE_Result _ltc_ecc_shared_secret(struct ecc_keypair *private_key,
					 struct ecc_public_key *public_key,
					 void *secret,
					 unsigned long *secret_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int ltc_res = 0;
	ecc_key ltc_private_key = { };
	ecc_key ltc_public_key = { };
	size_t key_size_bytes = 0;

	/* Check the curves are the same */
	if (private_key->curve != public_key->curve)
		return TEE_ERROR_BAD_PARAMETERS;

	res = ecc_populate_ltc_private_key(&ltc_private_key, private_key,
					   0, &key_size_bytes);
	if (res != TEE_SUCCESS)
		goto out;
	res = ecc_populate_ltc_public_key(&ltc_public_key, public_key,
					  0, &key_size_bytes);
	if (res != TEE_SUCCESS)
		goto out;

	ltc_res = ecc_shared_secret(&ltc_private_key, &ltc_public_key,
				    secret, secret_len);
	if (ltc_res == CRYPT_OK)
		res = TEE_SUCCESS;
	else
		res = TEE_ERROR_BAD_PARAMETERS;

out:
	ecc_free(&ltc_private_key);
	ecc_free(&ltc_public_key);
	return res;
}

static const struct crypto_ecc_keypair_ops ecc_keypair_ops = {
	.generate = _ltc_ecc_generate_keypair,
	.sign = _ltc_ecc_sign,
	.shared_secret = _ltc_ecc_shared_secret,
};

static const struct crypto_ecc_public_ops ecc_public_key_ops = {
	.free = _ltc_ecc_free_public_key,
	.verify = _ltc_ecc_verify,
};

static const struct crypto_ecc_keypair_ops sm2_dsa_keypair_ops = {
	.generate = _ltc_ecc_generate_keypair,
	.sign = sm2_ltc_dsa_sign,
};

static const struct crypto_ecc_public_ops sm2_dsa_public_key_ops = {
	.free = _ltc_ecc_free_public_key,
	.verify = sm2_ltc_dsa_verify,
};

static const struct crypto_ecc_keypair_ops sm2_pke_keypair_ops = {
	.generate = _ltc_ecc_generate_keypair,
	.decrypt = sm2_ltc_pke_decrypt,
};

static const struct crypto_ecc_public_ops sm2_pke_public_key_ops = {
	.free = _ltc_ecc_free_public_key,
	.encrypt = sm2_ltc_pke_encrypt,
};

static const struct crypto_ecc_keypair_ops sm2_kep_keypair_ops = {
	.generate = _ltc_ecc_generate_keypair,
};

static const struct crypto_ecc_public_ops sm2_kep_public_key_ops = {
	.free = _ltc_ecc_free_public_key,
};

TEE_Result crypto_asym_alloc_ecc_keypair(struct ecc_keypair *s,
					 uint32_t key_type,
					 size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));

	switch (key_type) {
	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ECDH_KEYPAIR:

		switch (key_size_bits) {
			case 192:
				s->curve = TEE_ECC_CURVE_NIST_P192;
			break;
			case 224:
				s->curve = TEE_ECC_CURVE_NIST_P224;
			break;
			case 256:
				s->curve = TEE_ECC_CURVE_NIST_P256;
			break;
			case 384:
				s->curve = TEE_ECC_CURVE_NIST_P384;
			break;
			case 521:
				s->curve = TEE_ECC_CURVE_NIST_P521;
			break;
			default:
				return TEE_ERROR_NOT_IMPLEMENTED;
		}
		s->ops = &ecc_keypair_ops;
		break;
	case TEE_TYPE_SM2_DSA_KEYPAIR:
		if (!IS_ENABLED(_CFG_CORE_LTC_SM2_DSA))
			return TEE_ERROR_NOT_IMPLEMENTED;

		s->ops = &sm2_dsa_keypair_ops;
		break;
	case TEE_TYPE_SM2_PKE_KEYPAIR:
		if (!IS_ENABLED(_CFG_CORE_LTC_SM2_PKE))
			return TEE_ERROR_NOT_IMPLEMENTED;

		s->ops = &sm2_pke_keypair_ops;
		break;
	case TEE_TYPE_SM2_KEP_KEYPAIR:
		if (!IS_ENABLED(_CFG_CORE_LTC_SM2_KEP))
			return TEE_ERROR_NOT_IMPLEMENTED;

		s->ops = &sm2_kep_keypair_ops;
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (!bn_alloc_max(&s->d))
		goto err;
	if (!bn_alloc_max(&s->x))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;



	return TEE_SUCCESS;

err:
	s->ops = NULL;

	crypto_bignum_free(s->d);
	crypto_bignum_free(s->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_asym_alloc_ecc_public_key(struct ecc_public_key *s,
					    uint32_t key_type,
					    size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));

	switch (key_type) {
	case TEE_TYPE_ECDSA_PUBLIC_KEY:
	case TEE_TYPE_ECDH_PUBLIC_KEY:
		switch (key_size_bits) {
			case 192:
				s->curve = TEE_ECC_CURVE_NIST_P192;
			break;
			case 224:
				s->curve = TEE_ECC_CURVE_NIST_P224;
			break;
			case 256:
				s->curve = TEE_ECC_CURVE_NIST_P256;
			break;
			case 384:
				s->curve = TEE_ECC_CURVE_NIST_P384;
			break;
			case 521:
				s->curve = TEE_ECC_CURVE_NIST_P521;
			break;
			default:
				return TEE_ERROR_NOT_IMPLEMENTED;
		}
		s->ops = &ecc_public_key_ops;
		break;
	case TEE_TYPE_SM2_DSA_PUBLIC_KEY:
		if (!IS_ENABLED(_CFG_CORE_LTC_SM2_DSA))
			return TEE_ERROR_NOT_IMPLEMENTED;

		s->ops = &sm2_dsa_public_key_ops;
		break;
	case TEE_TYPE_SM2_PKE_PUBLIC_KEY:
		if (!IS_ENABLED(_CFG_CORE_LTC_SM2_PKE))
			return TEE_ERROR_NOT_IMPLEMENTED;

		s->ops = &sm2_pke_public_key_ops;
		break;
	case TEE_TYPE_SM2_KEP_PUBLIC_KEY:
		if (!IS_ENABLED(_CFG_CORE_LTC_SM2_KEP))
			return TEE_ERROR_NOT_IMPLEMENTED;

		s->ops = &sm2_kep_public_key_ops;
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	if (!bn_alloc_max(&s->x))
		goto err;
	if (!bn_alloc_max(&s->y))
		goto err;

	return TEE_SUCCESS;

err:
	s->ops = NULL;

	crypto_bignum_free(s->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/* x25519 adaptation layer */
TEE_Result generate_x25519_keypair( uint8_t *pubkey,
								 uint8_t *privkey,
								 size_t *pubkey_length,
								 size_t *privkey_length,
								 bool x509_public)
{
	int pubkey_type;
	int ret;
	curve25519_key key;


	ret = x25519_make_key(&sel4_prng, find_prng("fortuna"), &key);
	if (ret) {
		return TEE_ERROR_GENERIC;
	}

	/* Export Keys */
	pubkey_type = PK_PUBLIC;

	/* Export public key in x509 format*/
	if (x509_public) {
		pubkey_type |= PK_STD;
	}
	ret = x25519_export(pubkey, pubkey_length, pubkey_type, &key);
	if (ret) {
		return TEE_ERROR_GENERIC;
	}

	ret = x25519_export(privkey, privkey_length, PK_PRIVATE,  &key);
	if (ret) {
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;

}
