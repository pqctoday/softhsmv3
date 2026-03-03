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
 OSSLMLKEMPublicKey.h

 OpenSSL ML-KEM public (encapsulation) key class (FIPS 203)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLMLKEMPUBLICKEY_H
#define _SOFTHSM_V2_OSSLMLKEMPUBLICKEY_H

#include "config.h"
#include "MLKEMPublicKey.h"
#include <openssl/evp.h>

class OSSLMLKEMPublicKey : public MLKEMPublicKey
{
public:
	// Constructors
	OSSLMLKEMPublicKey();
	OSSLMLKEMPublicKey(const EVP_PKEY* inPKEY);

	// Destructor
	virtual ~OSSLMLKEMPublicKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);
	virtual unsigned long getOutputLength() const;  // returns 0 for KEM public keys

	// Override setters to invalidate cached pkey
	virtual void setParameterSet(CK_ULONG inParamSet);
	virtual void setValue(const ByteString& inValue);

	// Set from OpenSSL representation
	void setFromOSSL(const EVP_PKEY* inPKEY);

	// Retrieve the OpenSSL representation of the key (lazy-initialised)
	EVP_PKEY* getOSSLKey();

	// Map CKP_ML_KEM_* → OpenSSL name string ("mlkem512" etc.)
	static const char* paramSetToName(CK_ULONG ps);

private:
	// Cached OpenSSL key handle
	EVP_PKEY* pkey;

	// Build the OpenSSL key from parameterSet + value
	void createOSSLKey();
};

#endif // !_SOFTHSM_V2_OSSLMLKEMPUBLICKEY_H
