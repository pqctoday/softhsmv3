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
 OSSLMLKEMPublicKey.cpp

 OpenSSL ML-KEM public (encapsulation) key class (FIPS 203)
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLMLKEMPublicKey.h"
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>
#include <string.h>

/*static*/ const char* OSSLMLKEMPublicKey::type = "OpenSSL ML-KEM Public Key";

/*static*/ const char* OSSLMLKEMPublicKey::paramSetToName(CK_ULONG ps)
{
	switch (ps)
	{
		case CKP_ML_KEM_512:  return "mlkem512";
		case CKP_ML_KEM_768:  return "mlkem768";
		case CKP_ML_KEM_1024: return "mlkem1024";
		default:              return NULL;
	}
}

OSSLMLKEMPublicKey::OSSLMLKEMPublicKey() : pkey(NULL)
{
	parameterSet = CKP_ML_KEM_768;
}

OSSLMLKEMPublicKey::OSSLMLKEMPublicKey(const EVP_PKEY* inPKEY) : pkey(NULL)
{
	parameterSet = CKP_ML_KEM_768;
	setFromOSSL(inPKEY);
}

OSSLMLKEMPublicKey::~OSSLMLKEMPublicKey()
{
	EVP_PKEY_free(pkey);
}

bool OSSLMLKEMPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

unsigned long OSSLMLKEMPublicKey::getOutputLength() const
{
	return 0;
}

void OSSLMLKEMPublicKey::setParameterSet(CK_ULONG inParamSet)
{
	MLKEMPublicKey::setParameterSet(inParamSet);
	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLMLKEMPublicKey::setValue(const ByteString& inValue)
{
	MLKEMPublicKey::setValue(inValue);
	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLMLKEMPublicKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	if (inPKEY == NULL) return;

	// Detect parameter set from the key name
	CK_ULONG ps;
	if      (EVP_PKEY_is_a(inPKEY, "mlkem512"))  ps = CKP_ML_KEM_512;
	else if (EVP_PKEY_is_a(inPKEY, "mlkem768"))  ps = CKP_ML_KEM_768;
	else if (EVP_PKEY_is_a(inPKEY, "mlkem1024")) ps = CKP_ML_KEM_1024;
	else
	{
		ERROR_MSG("Unknown ML-KEM parameter set in setFromOSSL");
		return;
	}
	MLKEMPublicKey::setParameterSet(ps);

	// Extract raw encapsulation key bytes
	EVP_PKEY* key = const_cast<EVP_PKEY*>(inPKEY);
	size_t pubLen = 0;
	if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pubLen) || pubLen == 0)
	{
		ERROR_MSG("Could not determine ML-KEM public key length (0x%08X)", ERR_get_error());
		return;
	}
	ByteString pub;
	pub.resize(pubLen);
	if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, &pub[0], pubLen, &pubLen))
	{
		ERROR_MSG("Could not extract ML-KEM public key bytes (0x%08X)", ERR_get_error());
		return;
	}
	MLKEMPublicKey::setValue(pub);

	// Cache the key (own a reference)
	if (pkey) EVP_PKEY_free(pkey);
	pkey = EVP_PKEY_dup(key);
}

EVP_PKEY* OSSLMLKEMPublicKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();
	return pkey;
}

void OSSLMLKEMPublicKey::createOSSLKey()
{
	if (pkey != NULL) return;
	if (value.size() == 0) return;

	const char* keyName = paramSetToName(parameterSet);
	if (keyName == NULL)
	{
		ERROR_MSG("Unknown ML-KEM parameter set %lu in createOSSLKey", parameterSet);
		return;
	}

	OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
	if (bld == NULL)
	{
		ERROR_MSG("OSSL_PARAM_BLD_new failed");
		return;
	}
	if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
	                                       value.const_byte_str(), value.size()))
	{
		OSSL_PARAM_BLD_free(bld);
		ERROR_MSG("OSSL_PARAM_BLD_push_octet_string failed");
		return;
	}
	OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
	OSSL_PARAM_BLD_free(bld);
	if (params == NULL)
	{
		ERROR_MSG("OSSL_PARAM_BLD_to_param failed");
		return;
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, keyName, NULL);
	if (ctx == NULL)
	{
		OSSL_PARAM_free(params);
		ERROR_MSG("EVP_PKEY_CTX_new_from_name(%s) failed (0x%08X)", keyName, ERR_get_error());
		return;
	}
	if (EVP_PKEY_fromdata_init(ctx) <= 0)
	{
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(ctx);
		ERROR_MSG("EVP_PKEY_fromdata_init failed (0x%08X)", ERR_get_error());
		return;
	}
	if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
	{
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(ctx);
		ERROR_MSG("EVP_PKEY_fromdata (public) failed (0x%08X)", ERR_get_error());
		return;
	}
	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(ctx);
}
