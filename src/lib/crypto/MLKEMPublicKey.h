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
 MLKEMPublicKey.h

 Abstract base class for ML-KEM (FIPS 203) public (encapsulation) keys.
 Stores the raw encapsulation key bytes and the CKP_ML_KEM_* parameter set.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLKEMPUBLICKEY_H
#define _SOFTHSM_V2_MLKEMPUBLICKEY_H

#include "config.h"
#include "PublicKey.h"
#include "cryptoki.h"

// ML-KEM encapsulation key sizes per FIPS 203
// ML-KEM-512:  ek = 800 B,  ct = 768 B,  ss = 32 B
// ML-KEM-768:  ek = 1184 B, ct = 1088 B, ss = 32 B
// ML-KEM-1024: ek = 1568 B, ct = 1568 B, ss = 32 B

class MLKEMPublicKey : public PublicKey
{
public:
	// Run-time type identifier
	static const char* type;
	virtual bool isOfType(const char* inType);

	// Returns security strength in bits (128, 192, or 256)
	virtual unsigned long getBitLength() const;

	// PublicKey pure virtual: not meaningful for KEM public keys (returns 0)
	virtual unsigned long getOutputLength() const;

	// Returns the ciphertext length produced by encapsulation (768, 1088, or 1568 bytes)
	virtual unsigned long getCiphertextLength() const;

	// Parameter set (CKP_ML_KEM_512, CKP_ML_KEM_768, CKP_ML_KEM_1024)
	void setParameterSet(CK_ULONG ps);
	CK_ULONG getParameterSet() const;

	// Raw encapsulation key bytes
	void setValue(const ByteString& inValue);
	const ByteString& getValue() const;

	// Serialisation (4-byte LE parameterSet || raw key bytes)
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
	CK_ULONG parameterSet;  // CKP_ML_KEM_512/768/1024
	ByteString value;       // raw encapsulation key bytes
};

#endif // !_SOFTHSM_V2_MLKEMPUBLICKEY_H
