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
#include "MLKEMPrivateKey.h"
#include <string.h>

// ML-KEM-512:  dk = 1632 B, ct = 768 B,  ss = 32 B, strength = 128 bits
// ML-KEM-768:  dk = 2400 B, ct = 1088 B, ss = 32 B, strength = 192 bits
// ML-KEM-1024: dk = 3168 B, ct = 1568 B, ss = 32 B, strength = 256 bits

const char* MLKEMPrivateKey::type = "ML-KEM Private Key";

bool MLKEMPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

unsigned long MLKEMPrivateKey::getBitLength() const
{
	switch (parameterSet)
	{
		case CKP_ML_KEM_512:  return 128;
		case CKP_ML_KEM_768:  return 192;
		case CKP_ML_KEM_1024: return 256;
		default:              return 0;
	}
}

unsigned long MLKEMPrivateKey::getOutputLength() const
{
	// Shared secret is always 32 bytes for all ML-KEM variants (FIPS 203 §6.1)
	return 32;
}

unsigned long MLKEMPrivateKey::getCiphertextLength() const
{
	switch (parameterSet)
	{
		case CKP_ML_KEM_512:  return 768;
		case CKP_ML_KEM_768:  return 1088;
		case CKP_ML_KEM_1024: return 1568;
		default:              return 0;
	}
}

void MLKEMPrivateKey::setParameterSet(CK_ULONG inParamSet)
{
	parameterSet = inParamSet;
}

CK_ULONG MLKEMPrivateKey::getParameterSet() const
{
	return parameterSet;
}

void MLKEMPrivateKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

const ByteString& MLKEMPrivateKey::getValue() const
{
	return value;
}

ByteString MLKEMPrivateKey::serialise() const
{
	// 4-byte LE parameterSet || serialised PKCS#8 DER value
	ByteString s;
	CK_ULONG ps = parameterSet;
	s += ByteString((unsigned char*)&ps, sizeof(ps));
	s += value.serialise();
	return s;
}

bool MLKEMPrivateKey::deserialise(ByteString& serialised)
{
	if (serialised.size() < sizeof(CK_ULONG)) return false;
	memcpy(&parameterSet, serialised.byte_str(), sizeof(CK_ULONG));
	serialised = serialised.substr(sizeof(CK_ULONG));

	ByteString val = ByteString::chainDeserialise(serialised);
	setValue(val);
	return true;
}
