/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 OSSLECPrivateKey.cpp

 OpenSSL EC private key class — EVP_PKEY throughout (OpenSSL 3.x)
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "OSSLECPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>
#include <string.h>

// Constructors
OSSLECPrivateKey::OSSLECPrivateKey()
{
	pkey = NULL;
}

OSSLECPrivateKey::OSSLECPrivateKey(const EVP_PKEY* inPKEY)
{
	pkey = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLECPrivateKey::~OSSLECPrivateKey()
{
	EVP_PKEY_free(pkey);
}

// The type
/*static*/ const char* OSSLECPrivateKey::type = "OpenSSL EC Private Key";

// Check if the key is of the given type
bool OSSLECPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Get the base point order length
unsigned long OSSLECPrivateKey::getOrderLength() const
{
	if (ec.size() == 0)
		return 0;

	EC_GROUP* grp = OSSL::byteString2grp(ec);
	if (grp == NULL)
		return 0;

	BIGNUM* order = BN_new();
	if (order == NULL)
	{
		EC_GROUP_free(grp);
		return 0;
	}
	if (!EC_GROUP_get_order(grp, order, NULL))
	{
		BN_clear_free(order);
		EC_GROUP_free(grp);
		return 0;
	}
	unsigned long len = BN_num_bytes(order);
	BN_clear_free(order);
	EC_GROUP_free(grp);
	return len;
}

// Set from OpenSSL EVP_PKEY representation
void OSSLECPrivateKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	// Extract group name and build DER-encoded ECParameters
	char curve_name[80] = {};
	if (EVP_PKEY_get_utf8_string_param(inPKEY, OSSL_PKEY_PARAM_GROUP_NAME,
	                                   curve_name, sizeof(curve_name), NULL))
	{
		int nid = OBJ_sn2nid(curve_name);
		if (nid == NID_undef) nid = OBJ_ln2nid(curve_name);
		if (nid != NID_undef)
		{
			EC_GROUP* grp = EC_GROUP_new_by_curve_name(nid);
			if (grp)
			{
				ByteString inEC = OSSL::grp2ByteString(grp);
				setEC(inEC);
				EC_GROUP_free(grp);
			}
		}
	}

	// Extract private key scalar
	BIGNUM* bn_d = NULL;
	if (EVP_PKEY_get_bn_param(inPKEY, OSSL_PKEY_PARAM_PRIV_KEY, &bn_d) && bn_d)
	{
		ByteString inD = OSSL::bn2ByteString(bn_d);
		setD(inD);
		BN_clear_free(bn_d);
	}
}

// Setters for the EC private key components
void OSSLECPrivateKey::setD(const ByteString& inD)
{
	ECPrivateKey::setD(inD);

	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

// Setters for the EC public key components
void OSSLECPrivateKey::setEC(const ByteString& inEC)
{
	ECPrivateKey::setEC(inEC);

	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

// Retrieve the OpenSSL EVP_PKEY representation of the key (built lazily)
EVP_PKEY* OSSLECPrivateKey::getOSSLKey()
{
	if (pkey != NULL)
		return pkey;

	if (ec.size() == 0 || d.size() == 0)
		return NULL;

	// Decode DER-encoded ECParameters → EC_GROUP → curve short name
	EC_GROUP* grp = OSSL::byteString2grp(ec);
	if (grp == NULL)
		return NULL;

	int nid = EC_GROUP_get_curve_name(grp);
	const char* curve_name = OBJ_nid2sn(nid);

	if (curve_name == NULL)
	{
		EC_GROUP_free(grp);
		return NULL;
	}

	BIGNUM* bn_d = OSSL::byteString2bn(d);
	if (bn_d == NULL)
	{
		EC_GROUP_free(grp);
		return NULL;
	}

	OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
	if (bld == NULL)
	{
		BN_clear_free(bn_d);
		return NULL;
	}

	bool pld_ok = false;
	unsigned char* pub_buf = NULL;
	EC_POINT* pub_pt = EC_POINT_new(grp);
	if (pub_pt != NULL && EC_POINT_mul(grp, pub_pt, bn_d, NULL, NULL, NULL) == 1)
	{
		size_t pub_len = EC_POINT_point2oct(grp, pub_pt, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
		if (pub_len > 0)
		{
			pub_buf = (unsigned char*)malloc(pub_len);
			if (pub_buf != NULL)
			{
				if (EC_POINT_point2oct(grp, pub_pt, POINT_CONVERSION_UNCOMPRESSED, pub_buf, pub_len, NULL) > 0)
				{
					if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, 0) == 1 &&
						OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_d) == 1 &&
						OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_buf, pub_len) == 1)
					{
						pld_ok = true;
					}
				}
			}
		}
	}
	if (pub_pt != NULL) EC_POINT_free(pub_pt);
	EC_GROUP_free(grp);

	if (!pld_ok)
	{
		if (pub_buf != NULL) free(pub_buf);
		OSSL_PARAM_BLD_free(bld);
		BN_clear_free(bn_d);
		return NULL;
	}

	// bn_d and pub_buf must stay alive until OSSL_PARAM_BLD_to_param() copies it
	OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
	OSSL_PARAM_BLD_free(bld);

	BN_clear_free(bn_d);
	if (pub_buf != NULL) free(pub_buf);

	if (params == NULL)
		return NULL;

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (ctx == NULL)
	{
		OSSL_PARAM_free(params);
		return NULL;
	}

	// EVP_PKEY_KEYPAIR: OpenSSL will compute the public point from the private scalar
	if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
	    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
	{
		ERROR_MSG("Could not build EVP_PKEY for EC private key (0x%08X)", ERR_get_error());
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);

	return pkey;
}

// Encode into PKCS#8 DER
ByteString OSSLECPrivateKey::PKCS8Encode()
{
	ByteString der;
	EVP_PKEY* key = getOSSLKey();
	if (key == NULL) return der;

	PKCS8_PRIV_KEY_INFO* p8inf = EVP_PKEY2PKCS8(key);
	if (p8inf == NULL) return der;

	int len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL);
	if (len < 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		return der;
	}
	der.resize(len);
	unsigned char* priv = &der[0];
	int len2 = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &priv);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	if (len2 != len) der.wipe();
	return der;
}

// Decode from PKCS#8 BER
bool OSSLECPrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = ber.size();
	if (len <= 0) return false;
	const unsigned char* priv = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &priv, len);
	if (p8 == NULL) return false;
	EVP_PKEY* key = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (key == NULL) return false;
	setFromOSSL(key);
	EVP_PKEY_free(key);
	return true;
}
#endif
