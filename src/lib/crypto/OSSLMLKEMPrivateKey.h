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
 OSSLMLKEMPrivateKey.h

 OpenSSL ML-KEM private (decapsulation) key class (FIPS 203).
 CKA_VALUE stores PKCS#8 DER-encoded decapsulation key.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLMLKEMPRIVATEKEY_H
#define _SOFTHSM_V2_OSSLMLKEMPRIVATEKEY_H

#include "config.h"
#include "MLKEMPrivateKey.h"
#include <openssl/evp.h>

class OSSLMLKEMPrivateKey : public MLKEMPrivateKey
{
public:
	// Constructors
	OSSLMLKEMPrivateKey();
	OSSLMLKEMPrivateKey(const EVP_PKEY* inPKEY);

	// Destructor
	virtual ~OSSLMLKEMPrivateKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Override setters to invalidate cached pkey
	virtual void setParameterSet(CK_ULONG inParamSet);
	virtual void setValue(const ByteString& inValue);

	// Set from OpenSSL representation (encodes to PKCS#8 DER → value)
	void setFromOSSL(const EVP_PKEY* inPKEY);

	// PKCS#8 encode/decode
	ByteString PKCS8Encode();
	bool PKCS8Decode(const ByteString& ber);

	// Retrieve the OpenSSL representation of the key (lazy-initialised)
	EVP_PKEY* getOSSLKey();

private:
	// Cached OpenSSL key handle
	EVP_PKEY* pkey;

	// Build the OpenSSL key from PKCS#8 DER stored in value
	void createOSSLKey();
};

#endif // !_SOFTHSM_V2_OSSLMLKEMPRIVATEKEY_H
