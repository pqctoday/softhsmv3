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
 OSSLMLKEMPrivateKey.cpp

 OpenSSL ML-KEM private (decapsulation) key class (FIPS 203).
 CKA_VALUE stores PKCS#8 DER-encoded decapsulation key.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLMLKEMPrivateKey.h"
#include "OSSLMLKEMPublicKey.h"
#include <openssl/x509.h>
#include <openssl/err.h>
#include <string.h>

/*static*/ const char* OSSLMLKEMPrivateKey::type = "OpenSSL ML-KEM Private Key";

OSSLMLKEMPrivateKey::OSSLMLKEMPrivateKey() : pkey(NULL)
{
	parameterSet = CKP_ML_KEM_768;
}

OSSLMLKEMPrivateKey::OSSLMLKEMPrivateKey(const EVP_PKEY* inPKEY) : pkey(NULL)
{
	parameterSet = CKP_ML_KEM_768;
	setFromOSSL(inPKEY);
}

OSSLMLKEMPrivateKey::~OSSLMLKEMPrivateKey()
{
	EVP_PKEY_free(pkey);
}

bool OSSLMLKEMPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

void OSSLMLKEMPrivateKey::setParameterSet(CK_ULONG inParamSet)
{
	MLKEMPrivateKey::setParameterSet(inParamSet);
	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLMLKEMPrivateKey::setValue(const ByteString& inValue)
{
	MLKEMPrivateKey::setValue(inValue);
	if (pkey) { EVP_PKEY_free(pkey); pkey = NULL; }
}

void OSSLMLKEMPrivateKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	if (inPKEY == NULL) return;

	// Detect parameter set from key name
	CK_ULONG ps;
	if      (EVP_PKEY_is_a(inPKEY, "mlkem512"))  ps = CKP_ML_KEM_512;
	else if (EVP_PKEY_is_a(inPKEY, "mlkem768"))  ps = CKP_ML_KEM_768;
	else if (EVP_PKEY_is_a(inPKEY, "mlkem1024")) ps = CKP_ML_KEM_1024;
	else
	{
		ERROR_MSG("Unknown ML-KEM parameter set in setFromOSSL");
		return;
	}
	MLKEMPrivateKey::setParameterSet(ps);

	// Encode to PKCS#8 DER and store in value
	EVP_PKEY* key = const_cast<EVP_PKEY*>(inPKEY);
	PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(key);
	if (p8 == NULL)
	{
		ERROR_MSG("EVP_PKEY2PKCS8 failed (0x%08X)", ERR_get_error());
		return;
	}
	int len = i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
	if (len <= 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8);
		ERROR_MSG("i2d_PKCS8_PRIV_KEY_INFO failed");
		return;
	}
	ByteString der;
	der.resize(len);
	unsigned char* p = &der[0];
	i2d_PKCS8_PRIV_KEY_INFO(p8, &p);
	PKCS8_PRIV_KEY_INFO_free(p8);
	MLKEMPrivateKey::setValue(der);

	// Cache the key
	if (pkey) EVP_PKEY_free(pkey);
	pkey = EVP_PKEY_dup(key);
}

ByteString OSSLMLKEMPrivateKey::PKCS8Encode()
{
	return value;
}

bool OSSLMLKEMPrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = (int)ber.size();
	if (len <= 0) return false;
	const unsigned char* p = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, len);
	if (p8 == NULL)
	{
		ERROR_MSG("PKCS8Decode: d2i_PKCS8_PRIV_KEY_INFO failed (0x%08X)", ERR_get_error());
		return false;
	}
	EVP_PKEY* key = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (key == NULL)
	{
		ERROR_MSG("PKCS8Decode: EVP_PKCS82PKEY failed (0x%08X)", ERR_get_error());
		return false;
	}
	setFromOSSL(key);
	EVP_PKEY_free(key);
	return true;
}

EVP_PKEY* OSSLMLKEMPrivateKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();
	return pkey;
}

void OSSLMLKEMPrivateKey::createOSSLKey()
{
	if (pkey != NULL) return;
	if (value.size() == 0) return;

	int len = (int)value.size();
	const unsigned char* p = value.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, len);
	if (p8 == NULL)
	{
		ERROR_MSG("createOSSLKey: d2i_PKCS8_PRIV_KEY_INFO failed (0x%08X)", ERR_get_error());
		return;
	}
	pkey = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (pkey == NULL)
		ERROR_MSG("createOSSLKey: EVP_PKCS82PKEY failed (0x%08X)", ERR_get_error());
}
