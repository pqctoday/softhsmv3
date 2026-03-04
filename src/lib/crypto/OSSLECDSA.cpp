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
 OSSLECDSA.cpp

 OpenSSL ECDSA asymmetric algorithm implementation — EVP_PKEY throughout (OpenSSL 3.x)
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "OSSLECDSA.h"
#include "CryptoFactory.h"
#include "ECParameters.h"
#include "OSSLECKeyPair.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/ecdsa.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <string.h>

// Helper: convert OpenSSL DER-encoded ECDSA_SIG to raw r||s (PKCS#11 format)
static bool derToRawSig(const unsigned char* der, size_t derLen,
                        unsigned char* raw, size_t orderLen)
{
	const unsigned char* p = der;
	ECDSA_SIG* sig = d2i_ECDSA_SIG(NULL, &p, (long)derLen);
	if (sig == NULL)
		return false;

	const BIGNUM* bn_r = NULL;
	const BIGNUM* bn_s = NULL;
	ECDSA_SIG_get0(sig, &bn_r, &bn_s);

	memset(raw, 0, 2 * orderLen);
	BN_bn2bin(bn_r, raw + orderLen - BN_num_bytes(bn_r));
	BN_bn2bin(bn_s, raw + 2 * orderLen - BN_num_bytes(bn_s));
	ECDSA_SIG_free(sig);
	return true;
}

// Helper: convert raw r||s (PKCS#11 format) to DER-encoded ECDSA_SIG
// Returns DER buffer (caller must OPENSSL_free) and sets derLen. Returns NULL on error.
static unsigned char* rawSigToDer(const unsigned char* raw, size_t orderLen, size_t* derLen)
{
	ECDSA_SIG* sig = ECDSA_SIG_new();
	if (sig == NULL)
		return NULL;

	BIGNUM* bn_r = BN_bin2bn(raw, orderLen, NULL);
	BIGNUM* bn_s = BN_bin2bn(raw + orderLen, orderLen, NULL);
	if (bn_r == NULL || bn_s == NULL || !ECDSA_SIG_set0(sig, bn_r, bn_s))
	{
		BN_free(bn_r);
		BN_free(bn_s);
		ECDSA_SIG_free(sig);
		return NULL;
	}

	unsigned char* der = NULL;
	int len = i2d_ECDSA_SIG(sig, &der);
	ECDSA_SIG_free(sig);
	if (len <= 0)
		return NULL;

	*derLen = (size_t)len;
	return der;
}

// Signing functions
bool OSSLECDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		     ByteString& signature, const AsymMech::Type mechanism,
		     const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	const EVP_MD* md = NULL;

	if (mechanism != AsymMech::ECDSA)
	{
		switch (mechanism)
		{
			case AsymMech::ECDSA_SHA1:     md = EVP_sha1();     break;
			case AsymMech::ECDSA_SHA224:   md = EVP_sha224();   break;
			case AsymMech::ECDSA_SHA256:   md = EVP_sha256();   break;
			case AsymMech::ECDSA_SHA384:   md = EVP_sha384();   break;
			case AsymMech::ECDSA_SHA512:   md = EVP_sha512();   break;
			case AsymMech::ECDSA_SHA3_224: md = EVP_sha3_224(); break;
			case AsymMech::ECDSA_SHA3_256: md = EVP_sha3_256(); break;
			case AsymMech::ECDSA_SHA3_384: md = EVP_sha3_384(); break;
			case AsymMech::ECDSA_SHA3_512: md = EVP_sha3_512(); break;
			default:
				ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
				return false;
		}
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLECPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	OSSLECPrivateKey* pk = (OSSLECPrivateKey*) privateKey;
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL private key");
		return false;
	}

	size_t orderLen = pk->getOrderLength();
	if (orderLen == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}

	// Perform the signature operation — result is DER SEQUENCE{r, s}
	ByteString derSig;

	if (md == NULL)
	{
		// Raw ECDSA: sign the pre-hashed bytes directly via EVP_PKEY_sign
		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (ctx == NULL || EVP_PKEY_sign_init(ctx) <= 0)
		{
			ERROR_MSG("ECDSA sign init failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
		size_t derLen = 0;
		// Query required output size
		if (EVP_PKEY_sign(ctx, NULL, &derLen,
		                  dataToSign.const_byte_str(), dataToSign.size()) <= 0)
		{
			ERROR_MSG("ECDSA sign size query failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
		derSig.resize(derLen);
		if (EVP_PKEY_sign(ctx, &derSig[0], &derLen,
		                  dataToSign.const_byte_str(), dataToSign.size()) <= 0)
		{
			ERROR_MSG("ECDSA sign failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			return false;
		}
		EVP_PKEY_CTX_free(ctx);
		derSig.resize(derLen);
	}
	else
	{
		// Hash-then-sign via EVP_DigestSign
		EVP_MD_CTX* ctx = EVP_MD_CTX_new();
		if (ctx == NULL || EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) <= 0)
		{
			ERROR_MSG("ECDSA DigestSign init failed (0x%08X)", ERR_get_error());
			EVP_MD_CTX_free(ctx);
			return false;
		}
		size_t derLen = 0;
		if (EVP_DigestSign(ctx, NULL, &derLen,
		                   dataToSign.const_byte_str(), dataToSign.size()) <= 0)
		{
			ERROR_MSG("ECDSA DigestSign size query failed (0x%08X)", ERR_get_error());
			EVP_MD_CTX_free(ctx);
			return false;
		}
		derSig.resize(derLen);
		if (EVP_DigestSign(ctx, &derSig[0], &derLen,
		                   dataToSign.const_byte_str(), dataToSign.size()) <= 0)
		{
			ERROR_MSG("ECDSA DigestSign failed (0x%08X)", ERR_get_error());
			EVP_MD_CTX_free(ctx);
			return false;
		}
		EVP_MD_CTX_free(ctx);
		derSig.resize(derLen);
	}

	// Convert DER SEQUENCE{r,s} → raw r||s (PKCS#11 format)
	signature.resize(2 * orderLen);
	if (!derToRawSig(derSig.const_byte_str(), derSig.size(), &signature[0], orderLen))
	{
		ERROR_MSG("ECDSA DER to raw signature conversion failed");
		return false;
	}
	return true;
}

bool OSSLECDSA::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
			 const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ECDSA does not support multi part signing");
	return false;
}

bool OSSLECDSA::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("ECDSA does not support multi part signing");
	return false;
}

bool OSSLECDSA::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("ECDSA does not support multi part signing");
	return false;
}

// Verification functions
bool OSSLECDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		       const ByteString& signature, const AsymMech::Type mechanism,
		       const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	const EVP_MD* md = NULL;

	if (mechanism != AsymMech::ECDSA)
	{
		switch (mechanism)
		{
			case AsymMech::ECDSA_SHA1:     md = EVP_sha1();     break;
			case AsymMech::ECDSA_SHA224:   md = EVP_sha224();   break;
			case AsymMech::ECDSA_SHA256:   md = EVP_sha256();   break;
			case AsymMech::ECDSA_SHA384:   md = EVP_sha384();   break;
			case AsymMech::ECDSA_SHA512:   md = EVP_sha512();   break;
			case AsymMech::ECDSA_SHA3_224: md = EVP_sha3_224(); break;
			case AsymMech::ECDSA_SHA3_256: md = EVP_sha3_256(); break;
			case AsymMech::ECDSA_SHA3_384: md = EVP_sha3_384(); break;
			case AsymMech::ECDSA_SHA3_512: md = EVP_sha3_512(); break;
			default:
				ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
				return false;
		}
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(OSSLECPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	OSSLECPublicKey* pk = (OSSLECPublicKey*) publicKey;
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");
		return false;
	}

	size_t orderLen = pk->getOrderLength();
	if (orderLen == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}
	if (signature.size() != 2 * orderLen)
	{
		ERROR_MSG("Invalid buffer length");
		return false;
	}

	// Convert raw r||s → DER SEQUENCE{r,s}
	size_t derLen = 0;
	unsigned char* derSig = rawSigToDer(signature.const_byte_str(), orderLen, &derLen);
	if (derSig == NULL)
	{
		ERROR_MSG("ECDSA raw to DER signature conversion failed");
		return false;
	}

	int ret;

	if (md == NULL)
	{
		// Raw ECDSA: verify the pre-hashed bytes
		EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (ctx == NULL || EVP_PKEY_verify_init(ctx) <= 0)
		{
			ERROR_MSG("ECDSA verify init failed (0x%08X)", ERR_get_error());
			EVP_PKEY_CTX_free(ctx);
			OPENSSL_free(derSig);
			return false;
		}
		ret = EVP_PKEY_verify(ctx, derSig, derLen,
		                      originalData.const_byte_str(), originalData.size());
		EVP_PKEY_CTX_free(ctx);
	}
	else
	{
		// Hash-then-verify
		EVP_MD_CTX* ctx = EVP_MD_CTX_new();
		if (ctx == NULL || EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) <= 0)
		{
			ERROR_MSG("ECDSA DigestVerify init failed (0x%08X)", ERR_get_error());
			EVP_MD_CTX_free(ctx);
			OPENSSL_free(derSig);
			return false;
		}
		ret = EVP_DigestVerify(ctx, derSig, derLen,
		                       originalData.const_byte_str(), originalData.size());
		EVP_MD_CTX_free(ctx);
	}

	OPENSSL_free(derSig);

	if (ret != 1)
	{
		if (ret < 0)
			ERROR_MSG("ECDSA verify failed (0x%08X)", ERR_get_error());
		return false;
	}
	return true;
}

bool OSSLECDSA::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			   const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ECDSA does not support multi part verifying");
	return false;
}

bool OSSLECDSA::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("ECDSA does not support multi part verifying");
	return false;
}

bool OSSLECDSA::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("ECDSA does not support multi part verifying");
	return false;
}

// Encryption functions
bool OSSLECDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
			ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ECDSA does not support encryption");
	return false;
}

// Decryption functions
bool OSSLECDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
			ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ECDSA does not support decryption");
	return false;
}

// Key factory
bool OSSLECDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) || (parameters == NULL))
		return false;

	if (!parameters->areOfType(ECParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ECDSA key generation");
		return false;
	}

	ECParameters* params = (ECParameters*) parameters;

	// Determine the curve short name from DER-encoded ECParameters
	EC_GROUP* grp = OSSL::byteString2grp(params->getEC());
	if (grp == NULL)
	{
		ERROR_MSG("Failed to decode EC group for ECDSA key generation");
		return false;
	}
	int nid = EC_GROUP_get_curve_name(grp);
	const char* curve_name = OBJ_nid2sn(nid);
	EC_GROUP_free(grp);

	if (curve_name == NULL)
	{
		ERROR_MSG("Failed to get curve name for ECDSA key generation");
		return false;
	}

	// Generate the key-pair via EVP_PKEY_CTX
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("Failed to instantiate EVP_PKEY_CTX for EC key generation");
		return false;
	}

	OSSL_PARAM keygen_params[2];
	keygen_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
	                                                     (char*)curve_name, 0);
	keygen_params[1] = OSSL_PARAM_construct_end();

	if (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_params(ctx, keygen_params) <= 0 ||
	    EVP_PKEY_generate(ctx, &pkey) <= 0)
	{
		ERROR_MSG("ECDSA key generation failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	// Create an asymmetric key-pair object to return
	OSSLECKeyPair* kp = new OSSLECKeyPair();

	((OSSLECPublicKey*) kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLECPrivateKey*) kp->getPrivateKey())->setFromOSSL(pkey);

	*ppKeyPair = kp;

	// Release the key
	EVP_PKEY_free(pkey);

	return true;
}

unsigned long OSSLECDSA::getMinKeySize()
{
	// Smallest EC group is secp112r1
	return 112;
}

unsigned long OSSLECDSA::getMaxKeySize()
{
	// Biggest EC group is secp521r1
	return 521;
}

bool OSSLECDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) || (serialisedData.size() == 0))
		return false;

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLECKeyPair* kp = new OSSLECKeyPair();

	bool rv = true;

	if (!((ECPublicKey*) kp->getPublicKey())->deserialise(dPub))
		rv = false;

	if (!((ECPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
		rv = false;

	if (!rv)
	{
		delete kp;
		return false;
	}

	*ppKeyPair = kp;

	return true;
}

bool OSSLECDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) || (serialisedData.size() == 0))
		return false;

	OSSLECPublicKey* pub = new OSSLECPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;
		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLECDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) || (serialisedData.size() == 0))
		return false;

	OSSLECPrivateKey* priv = new OSSLECPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;
		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLECDSA::newPublicKey()
{
	return (PublicKey*) new OSSLECPublicKey();
}

PrivateKey* OSSLECDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLECPrivateKey();
}

AsymmetricParameters* OSSLECDSA::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool OSSLECDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
		return false;

	ECParameters* params = new ECParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;
		return false;
	}

	*ppParams = params;

	return true;
}
#endif
