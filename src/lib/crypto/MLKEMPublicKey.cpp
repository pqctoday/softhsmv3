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

#include "config.h"
#include "MLKEMPublicKey.h"
#include <string.h>

// ML-KEM-512:  ek = 800 B,  ct = 768 B,  ss = 32 B, strength = 128 bits
// ML-KEM-768:  ek = 1184 B, ct = 1088 B, ss = 32 B, strength = 192 bits
// ML-KEM-1024: ek = 1568 B, ct = 1568 B, ss = 32 B, strength = 256 bits

const char* MLKEMPublicKey::type = "ML-KEM Public Key";

bool MLKEMPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

unsigned long MLKEMPublicKey::getBitLength() const
{
	switch (parameterSet)
	{
		case CKP_ML_KEM_512:  return 128;
		case CKP_ML_KEM_768:  return 192;
		case CKP_ML_KEM_1024: return 256;
		default:              return 0;
	}
}

unsigned long MLKEMPublicKey::getOutputLength() const
{
	return 0;
}

unsigned long MLKEMPublicKey::getCiphertextLength() const
{
	switch (parameterSet)
	{
		case CKP_ML_KEM_512:  return 768;
		case CKP_ML_KEM_768:  return 1088;
		case CKP_ML_KEM_1024: return 1568;
		default:              return 0;
	}
}

void MLKEMPublicKey::setParameterSet(CK_ULONG inParamSet)
{
	parameterSet = inParamSet;
}

CK_ULONG MLKEMPublicKey::getParameterSet() const
{
	return parameterSet;
}

void MLKEMPublicKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

const ByteString& MLKEMPublicKey::getValue() const
{
	return value;
}

ByteString MLKEMPublicKey::serialise() const
{
	// 4-byte LE parameterSet || serialised value
	ByteString s;
	CK_ULONG ps = parameterSet;
	s += ByteString((unsigned char*)&ps, sizeof(ps));
	s += value.serialise();
	return s;
}

bool MLKEMPublicKey::deserialise(ByteString& serialised)
{
	if (serialised.size() < sizeof(CK_ULONG)) return false;
	memcpy(&parameterSet, serialised.byte_str(), sizeof(CK_ULONG));
	serialised = serialised.substr(sizeof(CK_ULONG));

	ByteString val = ByteString::chainDeserialise(serialised);
	setValue(val);
	return true;
}
