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
 MLKEMPrivateKey.h

 Abstract base class for ML-KEM (FIPS 203) private (decapsulation) keys.
 The key material is stored as PKCS#8 DER (EVP_PKEY2PKCS8), which includes
 the parameter set in the AlgorithmIdentifier OID.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLKEMPRIVATEKEY_H
#define _SOFTHSM_V2_MLKEMPRIVATEKEY_H

#include "config.h"
#include "PrivateKey.h"
#include "cryptoki.h"

class MLKEMPrivateKey : public PrivateKey
{
public:
	// Run-time type identifier
	static const char* type;
	virtual bool isOfType(const char* inType);

	// Returns security strength in bits (128, 192, or 256)
	virtual unsigned long getBitLength() const;

	// Returns the shared secret length (always 32 bytes for all ML-KEM variants)
	virtual unsigned long getOutputLength() const;

	// Returns the ciphertext length (768, 1088, or 1568 bytes)
	virtual unsigned long getCiphertextLength() const;

	// Parameter set (CKP_ML_KEM_512, CKP_ML_KEM_768, CKP_ML_KEM_1024)
	void setParameterSet(CK_ULONG ps);
	CK_ULONG getParameterSet() const;

	// PKCS#8 DER-encoded private key
	void setValue(const ByteString& inValue);
	const ByteString& getValue() const;

	// Serialisation (4-byte LE parameterSet || PKCS#8 DER bytes)
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
	CK_ULONG parameterSet;  // CKP_ML_KEM_512/768/1024
	ByteString value;       // PKCS#8 DER-encoded decapsulation key
};

#endif // !_SOFTHSM_V2_MLKEMPRIVATEKEY_H
