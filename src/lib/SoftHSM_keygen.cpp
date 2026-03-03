/*
 * Copyright (c) 2022 NLnet Labs
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
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
 SoftHSM_keygen.cpp

 PKCS#11 key generation, wrapping/unwrapping, derivation:
 C_GenerateKey, C_GenerateKeyPair, C_WrapKey, C_UnwrapKey, C_DeriveKey.
 Key-generation helpers: generateGeneric, generateAES, generateRSA, generateEC,
 generateED, generateMLDSA, generateSLHDSA, generateMLKEM.
 Derivation helpers: deriveECDH, deriveEDDSA, deriveSymmetric.
 Key-material helpers: getRSA/EC/ED/MLDSA/SLHDSA/MLKEMPrivateKey/PublicKey,
 getECDH/EDDHPublicKey, getSymmetricKey, setRSA/EC/EDPrivateKey.
 Mechanism-param helpers: MechParamCheckRSAPKCSOAEP, MechParamCheckRSAAESKEYWRAP.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "access.h"
#include "SoftHSM.h"
#include "SoftHSMHelpers.h"
#include "HandleManager.h"
#include "CryptoFactory.h"
#include "AsymmetricAlgorithm.h"
#include "SymmetricAlgorithm.h"
#include "AESKey.h"
#include "DerUtil.h"
#include "RNG.h"
#include "RSAParameters.h"
#include "RSAPublicKey.h"
#include "RSAPrivateKey.h"
#include "ECPublicKey.h"
#include "ECPrivateKey.h"
#include "ECParameters.h"
#include "EDPublicKey.h"
#include "EDPrivateKey.h"
#include "MLDSAPublicKey.h"
#include "MLDSAPrivateKey.h"
#include "MLDSAParameters.h"
#include "SLHDSAPublicKey.h"
#include "SLHDSAPrivateKey.h"
#include "SLHDSAParameters.h"
#include "OSSLMLDSAPublicKey.h"
#include "OSSLMLDSAPrivateKey.h"
#include "OSSLSLHDSAPublicKey.h"
#include "OSSLSLHDSAPrivateKey.h"
#include "MLKEMPublicKey.h"
#include "MLKEMPrivateKey.h"
#include "MLKEMParameters.h"
#include "OSSLMLKEMPublicKey.h"
#include "OSSLMLKEMPrivateKey.h"
#include "OSSLMLKEM.h"
#include "cryptoki.h"
#include "P11Attributes.h"
#include "P11Objects.h"
#include "SlotManager.h"
#include "odd.h"

// Generate a secret key or a domain parameter set using the specified mechanism
CK_RV SoftHSM::C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pTemplate == NULL_PTR && ulCount != 0) return CKR_ARGUMENTS_BAD;
	if (phKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the mechanism, only accept DSA and DH parameters
	// and symmetric ciphers
	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	switch (pMechanism->mechanism)
	{
#ifndef WITH_FIPS
		case CKM_AES_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_AES;
			break;
		case CKM_GENERIC_SECRET_KEY_GEN:
			objClass = CKO_SECRET_KEY;
			keyType = CKK_GENERIC_SECRET;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Extract information from the template that is needed to create the object.
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	bool isImplicit = true;
	extractObjectInformation(pTemplate, ulCount, objClass, keyType, dummy, isOnToken, isPrivate, isImplicit);

	// Report errors and/or unexpected usage.
	if (objClass != CKO_SECRET_KEY && objClass != CKO_DOMAIN_PARAMETERS)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (pMechanism->mechanism == CKM_AES_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_AES))
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_GENERIC_SECRET_KEY_GEN &&
	    (objClass != CKO_SECRET_KEY || keyType != CKK_GENERIC_SECRET))
		return CKR_TEMPLATE_INCONSISTENT;

	// Check authorization
	CK_RV rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}


	// Generate AES secret key
	if (pMechanism->mechanism == CKM_AES_KEY_GEN)
	{
		return this->generateAES(hSession, pTemplate, ulCount, phKey, isOnToken, isPrivate);
	}

	// Generate generic secret key
	if (pMechanism->mechanism == CKM_GENERIC_SECRET_KEY_GEN)
	{
		return this->generateGeneric(hSession, pTemplate, ulCount, phKey, isOnToken, isPrivate);
	}

	return CKR_GENERAL_ERROR;
}

// Generate a key-pair using the specified mechanism
CK_RV SoftHSM::C_GenerateKeyPair
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pPublicKeyTemplate == NULL_PTR && ulPublicKeyAttributeCount != 0) return CKR_ARGUMENTS_BAD;
	if (pPrivateKeyTemplate == NULL_PTR && ulPrivateKeyAttributeCount != 0) return CKR_ARGUMENTS_BAD;
	if (phPublicKey == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phPrivateKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the mechanism, only accept RSA, DSA, EC and DH key pair generation.
	CK_KEY_TYPE keyType;
	switch (pMechanism->mechanism)
	{
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			keyType = CKK_RSA;
			break;
#ifdef WITH_ECC
		case CKM_EC_KEY_PAIR_GEN:
			keyType = CKK_EC;
			break;
#endif
#ifdef WITH_EDDSA
		case CKM_EC_EDWARDS_KEY_PAIR_GEN:
			keyType = CKK_EC_EDWARDS;
			break;
		case CKM_EC_MONTGOMERY_KEY_PAIR_GEN:
			keyType = CKK_EC_MONTGOMERY;
			break;
#endif
		case CKM_ML_DSA_KEY_PAIR_GEN:
			keyType = CKK_ML_DSA;
			break;
		case CKM_SLH_DSA_KEY_PAIR_GEN:
			keyType = CKK_SLH_DSA;
			break;
		case CKM_ML_KEM_KEY_PAIR_GEN:
			keyType = CKK_ML_KEM;
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}
	CK_CERTIFICATE_TYPE dummy;

	// Extract information from the public key template that is needed to create the object.
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_BBOOL ispublicKeyToken = CK_FALSE;
	CK_BBOOL ispublicKeyPrivate = CK_FALSE;
	bool isPublicKeyImplicit = true;
	extractObjectInformation(pPublicKeyTemplate, ulPublicKeyAttributeCount, publicKeyClass, keyType, dummy, ispublicKeyToken, ispublicKeyPrivate, isPublicKeyImplicit);

	// Report errors caused by accidental template mix-ups in the application using this cryptoki lib.
	if (publicKeyClass != CKO_PUBLIC_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN && keyType != CKK_RSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_EC_EDWARDS_KEY_PAIR_GEN && keyType != CKK_EC_EDWARDS)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_EC_MONTGOMERY_KEY_PAIR_GEN && keyType != CKK_EC_MONTGOMERY)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_ML_DSA_KEY_PAIR_GEN && keyType != CKK_ML_DSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_SLH_DSA_KEY_PAIR_GEN && keyType != CKK_SLH_DSA)
		return CKR_TEMPLATE_INCONSISTENT;

	// Extract information from the private key template that is needed to create the object.
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
	CK_BBOOL isprivateKeyToken = CK_FALSE;
	CK_BBOOL isprivateKeyPrivate = CK_TRUE;
	bool isPrivateKeyImplicit = true;
	extractObjectInformation(pPrivateKeyTemplate, ulPrivateKeyAttributeCount, privateKeyClass, keyType, dummy, isprivateKeyToken, isprivateKeyPrivate, isPrivateKeyImplicit);

	// Report errors caused by accidental template mix-ups in the application using this cryptoki lib.
	if (privateKeyClass != CKO_PRIVATE_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN && keyType != CKK_RSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_EC_EDWARDS_KEY_PAIR_GEN && keyType != CKK_EC_EDWARDS)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_EC_MONTGOMERY_KEY_PAIR_GEN && keyType != CKK_EC_MONTGOMERY)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_ML_DSA_KEY_PAIR_GEN && keyType != CKK_ML_DSA)
		return CKR_TEMPLATE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_SLH_DSA_KEY_PAIR_GEN && keyType != CKK_SLH_DSA)
		return CKR_TEMPLATE_INCONSISTENT;

	// Check user credentials
	CK_RV rv = haveWrite(session->getState(), ispublicKeyToken || isprivateKeyToken, ispublicKeyPrivate || isprivateKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Generate RSA keys
	if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN)
	{
			return this->generateRSA(hSession,
									 pPublicKeyTemplate, ulPublicKeyAttributeCount,
									 pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
									 phPublicKey, phPrivateKey,
									 ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}


	// Generate EC (Weierstrass curve) keys
	if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN)
	{
			return this->generateEC(hSession,
									 pPublicKeyTemplate, ulPublicKeyAttributeCount,
									 pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
									 phPublicKey, phPrivateKey,
									 ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	// Generate Edwards / Montgomery keys
	if (pMechanism->mechanism == CKM_EC_EDWARDS_KEY_PAIR_GEN ||
	    pMechanism->mechanism == CKM_EC_MONTGOMERY_KEY_PAIR_GEN)
	{
			return this->generateED(hSession,
									 pPublicKeyTemplate, ulPublicKeyAttributeCount,
									 pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
									 phPublicKey, phPrivateKey,
									 ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	// Generate ML-DSA keys (FIPS 204)
	if (pMechanism->mechanism == CKM_ML_DSA_KEY_PAIR_GEN)
	{
		return this->generateMLDSA(hSession,
			pPublicKeyTemplate, ulPublicKeyAttributeCount,
			pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
			phPublicKey, phPrivateKey,
			ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	// Generate SLH-DSA keys (FIPS 205)
	if (pMechanism->mechanism == CKM_SLH_DSA_KEY_PAIR_GEN)
	{
		return this->generateSLHDSA(hSession,
			pPublicKeyTemplate, ulPublicKeyAttributeCount,
			pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
			phPublicKey, phPrivateKey,
			ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	// Generate ML-KEM keys (FIPS 203)
	if (pMechanism->mechanism == CKM_ML_KEM_KEY_PAIR_GEN)
	{
		return this->generateMLKEM(hSession,
			pPublicKeyTemplate, ulPublicKeyAttributeCount,
			pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
			phPublicKey, phPrivateKey,
			ispublicKeyToken, ispublicKeyPrivate, isprivateKeyToken, isprivateKeyPrivate);
	}

	return CKR_GENERAL_ERROR;
}


// PKCS#7 padding
size_t SoftHSM::RFC5652Pad(ByteString &keydata, size_t blocksize)
{
	size_t wrappedlen = keydata.size();
	auto padbytes = blocksize - (wrappedlen % blocksize);
	if(padbytes == 0)
		padbytes += blocksize;

	keydata.resize(wrappedlen + padbytes);
	memset(&keydata[wrappedlen], static_cast<char>(padbytes), padbytes);
	return keydata.size();
}


// CKM_AES_KEY_WRAP unpadding
size_t SoftHSM::RFC3394Pad(ByteString &keydata)
{
	size_t wrappedlen = keydata.size();

	// [PKCS#11 v2.40, 2.14.3 AES Key Wrap]
	// A key whose length is not a multiple of the AES Key Wrap block
	// size (8 bytes) will be zero padded to fit.
	auto alignment = wrappedlen % 8;
	if (alignment != 0)
	{
		keydata.resize(wrappedlen + 8 - alignment);
		memset(&keydata[wrappedlen], 0, 8 - alignment);
	}
	return keydata.size();
}

// PKCS#7 padding
bool SoftHSM::RFC5652Unpad(ByteString &padded, size_t blocksize)
{
	auto wrappedlen = padded.size();

	if( wrappedlen % blocksize != 0)
	{
		DEBUG_MSG("padded buffer length %d is not a multiple of %d", wrappedlen, blocksize);
		return false;
	}

	auto padbyte = padded[wrappedlen-1];

	if( padbyte == 0 || padbyte > blocksize )
	{
		DEBUG_MSG("invalid padbyte value %d, larger than blocksize %d", padbyte, blocksize);
		return false;
	}

	for(auto i = wrappedlen-padbyte; i<wrappedlen; i++)
	{
		if( padded[i] != padbyte )
		{
			DEBUG_MSG("invalid padding byte %d at position %d", padded[i], i);
			return false;
		}
	}

	padded.resize(wrappedlen - padbyte); // forget padding
	return true;
}

// CKM_AES_KEY_WRAP padding
inline bool SoftHSM::RFC3394Unpad(ByteString &)
{
	// there is no unpadding operation, as the padding
	// does not contain any padding length info
	return true;
}


// Internal: Wrap blob using symmetric key
CK_RV SoftHSM::WrapKeySym
(
	CK_MECHANISM_PTR pMechanism,
	Token* token,
	OSObject* wrapKey,
	ByteString& keydata,
	ByteString& wrapped
)
{
	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymWrap::Type mode = SymWrap::Unknown;
	size_t bb = 8;
	size_t blocksize = 0;
	auto wrappedlen = keydata.size();

	switch(pMechanism->mechanism) {
#ifdef HAVE_AES_KEY_WRAP
		case CKM_AES_KEY_WRAP:
			wrappedlen = RFC3394Pad(keydata);
			if ((wrappedlen < 16) || ((wrappedlen % 8) != 0))
				return CKR_KEY_SIZE_RANGE;
			algo = SymAlgo::AES;
			mode = SymWrap::AES_KEYWRAP;
			break;
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			algo = SymAlgo::AES;
			mode = SymWrap::AES_KEYWRAP_PAD;
			break;
#endif
		case CKM_AES_CBC:
			algo = SymAlgo::AES;
			break;
			
		case CKM_AES_CBC_PAD:
			blocksize = 16;
			wrappedlen = RFC5652Pad(keydata, blocksize);
			algo = SymAlgo::AES;
			break;
			
		default:
			return CKR_MECHANISM_INVALID;
	}
	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* wrappingkey = new SymmetricKey();

	if (getSymmetricKey(wrappingkey, token, wrapKey) != CKR_OK)
	{
		cipher->recycleKey(wrappingkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	wrappingkey->setBitLen(wrappingkey->getKeyBits().size() * bb);

	ByteString iv;
	ByteString encryptedFinal;

	switch(pMechanism->mechanism) {

		case CKM_AES_CBC:
	        case CKM_AES_CBC_PAD:
		default:
			// Wrap the key
			if (!cipher->wrapKey(wrappingkey, mode, keydata, wrapped))
			{
				cipher->recycleKey(wrappingkey);
				CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
				return CKR_GENERAL_ERROR;
			}
	}

	cipher->recycleKey(wrappingkey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
	return CKR_OK;
}

// Internal: Wrap blob using asymmetric key
CK_RV SoftHSM::WrapKeyAsym
(
	CK_MECHANISM_PTR pMechanism,
	Token* token,
	OSObject* wrapKey,
	ByteString& keydata,
	ByteString& wrapped
)
{
	const size_t bb = 8;
	AsymAlgo::Type algo = AsymAlgo::Unknown;
	AsymMech::Type mech = AsymMech::Unknown;

	CK_ULONG modulus_length;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_RSA_PKCS_OAEP:
			algo = AsymAlgo::RSA;
			if (!wrapKey->attributeExists(CKA_MODULUS_BITS))
				return CKR_GENERAL_ERROR;
			modulus_length = wrapKey->getUnsignedLongValue(CKA_MODULUS_BITS, 0);
			// adjust key bit length
			modulus_length /= bb;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			mech = AsymMech::RSA_PKCS;
			// RFC 3447 section 7.2.1
			if (keydata.size() > modulus_length - 11)
				return CKR_KEY_SIZE_RANGE;
			break;

		case CKM_RSA_PKCS_OAEP:
			mech = AsymMech::RSA_PKCS_OAEP;
			// SHA-1 is the only supported option
			// PKCS#11 2.40 draft 2 section 2.1.8: input length <= k-2-2hashLen
			if (keydata.size() > modulus_length - 2 - 2 * 160 / 8)
				return CKR_KEY_SIZE_RANGE;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	AsymmetricAlgorithm* cipher = CryptoFactory::i()->getAsymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	PublicKey* publicKey = cipher->newPublicKey();
	if (publicKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
		return CKR_HOST_MEMORY;
	}

	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_RSA_PKCS_OAEP:
			if (getRSAPublicKey((RSAPublicKey*)publicKey, token, wrapKey) != CKR_OK)
			{
				cipher->recyclePublicKey(publicKey);
				CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
				return CKR_GENERAL_ERROR;
			}
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}
	// Wrap the key
	if (!cipher->wrapKey(publicKey, keydata, wrapped, mech))
	{
		cipher->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	cipher->recyclePublicKey(publicKey);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);

	return CKR_OK;
}

// Internal: Wrap with mechanism RSA_AES_KEY_WRAP
CK_RV SoftHSM::WrapMechRsaAesKw
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	Token *token,
	OSObject *wrapKey,
	ByteString &keydata,
	ByteString &wrapped
)
{
	CK_RV rv = CKR_OK;
	ByteString wrapped_1; // buffer for the wrapped AES key;
	ByteString wrapped_2; // buffer for the wrapped target key;
	CK_RSA_AES_KEY_WRAP_PARAMS_PTR params = (CK_RSA_AES_KEY_WRAP_PARAMS_PTR)pMechanism->pParameter;
	CK_ULONG emphKeyLen = params->ulAESKeyBits / 8;
	CK_OBJECT_HANDLE hEmphKey = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS emphKeyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE emphKeyType = CKK_AES;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE emph_temp[] = {
		{CKA_CLASS, &emphKeyClass, sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE, &emphKeyType, sizeof(CK_KEY_TYPE)},
		{CKA_TOKEN, &bFalse, sizeof(CK_BBOOL)},
		{CKA_PRIVATE, &bTrue, sizeof(CK_BBOOL)},
		{CKA_WRAP, &bTrue, sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE, &bTrue, sizeof(CK_BBOOL)},
		{CKA_VALUE_LEN, &emphKeyLen, sizeof(CK_ULONG)}
	};

	// Generates temporary random AES key of ulAESKeyBits length.
	rv = this->generateAES(hSession, emph_temp, sizeof(emph_temp)/sizeof(CK_ATTRIBUTE), &hEmphKey, bFalse, bTrue);
	if (rv != CKR_OK)
	{
		// Remove secret that may have been created already when the function fails.
		if (hEmphKey != CK_INVALID_HANDLE)
		{
		    OSObject *emphKey = (OSObject *)handleManager->getObject(hEmphKey);
		    handleManager->destroyObject(hEmphKey);
		    if(emphKey) emphKey->destroyObject();
		    hEmphKey = CK_INVALID_HANDLE;
		}
		return rv;
	}

	OSObject *emphKey = (OSObject *)handleManager->getObject(hEmphKey);
	if (emphKey == NULL_PTR || !emphKey->isValid())
	{
		rv = CKR_FUNCTION_FAILED;
		handleManager->destroyObject(hEmphKey);
		if(emphKey) emphKey->destroyObject();
		hEmphKey = CK_INVALID_HANDLE;
		return rv;
	}

	CK_MECHANISM emphMech = {CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0};
	// Wraps the target key with the temporary AES key using CKM_AES_KEY_WRAP_PAD (RFC5649).
	rv = SoftHSM::WrapKeySym(&emphMech, token, emphKey, keydata, wrapped_2);
	if (rv != CKR_OK)
	{
		handleManager->destroyObject(hEmphKey);
		emphKey->destroyObject();
		hEmphKey = CK_INVALID_HANDLE;
		return rv;
	}

	// Get the AES emph key data
	ByteString emphkeydata;
	ByteString emphKeyValue = emphKey->getByteStringValue(CKA_VALUE);
	token->decrypt(emphKeyValue, emphkeydata);

	// Remove the emph key handle.
	handleManager->destroyObject(hEmphKey);
	emphKey->destroyObject();
	hEmphKey = CK_INVALID_HANDLE;

	CK_MECHANISM oaepMech = {CKM_RSA_PKCS_OAEP, params->pOAEPParams, sizeof(CK_RSA_PKCS_OAEP_PARAMS)};
	// Wraps the AES emph key with the wrapping RSA key using CKM_RSA_PKCS_OAEP with parameters of OAEPParams.
	rv = SoftHSM::WrapKeyAsym(&oaepMech, token, wrapKey, emphkeydata, wrapped_1);

	// Zeroizes the temporary AES emph key
	emphkeydata.wipe();
	emphKeyValue.wipe();

	if (rv != CKR_OK)
	{
		return rv;
	}

	// Concatenates two wrapped keys and outputs the concatenated blob.
	wrapped = wrapped_1 + wrapped_2;

	return rv;
}


// Wrap the specified key using the specified wrapping key and mechanism
CK_RV SoftHSM::C_WrapKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hWrappingKey,
	CK_OBJECT_HANDLE hKey,
	CK_BYTE_PTR pWrappedKey,
	CK_ULONG_PTR pulWrappedKeyLen
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pulWrappedKeyLen == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	CK_RV rv;
	// Check the mechanism, only accept advanced AES key wrapping and RSA
	switch(pMechanism->mechanism)
	{
#ifdef HAVE_AES_KEY_WRAP
		case CKM_AES_KEY_WRAP:
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
#endif
		case CKM_RSA_PKCS:
			// Does not handle optional init vector
			if (pMechanism->pParameter != NULL_PTR ||
                            pMechanism->ulParameterLen != 0)
				return CKR_ARGUMENTS_BAD;
			break;
		case CKM_RSA_PKCS_OAEP:
			rv = MechParamCheckRSAPKCSOAEP(pMechanism);
			if (rv != CKR_OK)
				return rv;
			break;
		case CKM_RSA_AES_KEY_WRAP:
			rv = MechParamCheckRSAAESKEYWRAP(pMechanism);
			if (rv != CKR_OK)
				return rv;
			break;
		case CKM_AES_CBC:
	        case CKM_AES_CBC_PAD:
			if (pMechanism->pParameter == NULL_PTR ||
                            pMechanism->ulParameterLen != 16)
                                return CKR_ARGUMENTS_BAD;
                        break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the wrapping key handle.
	OSObject *wrapKey = (OSObject *)handleManager->getObject(hWrappingKey);
	if (wrapKey == NULL_PTR || !wrapKey->isValid()) return CKR_WRAPPING_KEY_HANDLE_INVALID;

	CK_BBOOL isWrapKeyOnToken = wrapKey->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isWrapKeyPrivate = wrapKey->getBooleanValue(CKA_PRIVATE, true);

	// Check user credentials for the wrapping key
	rv = haveRead(session->getState(), isWrapKeyOnToken, isWrapKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");

		return rv;
	}

	// Check wrapping key class and type
	if ((pMechanism->mechanism == CKM_AES_KEY_WRAP || pMechanism->mechanism == CKM_AES_KEY_WRAP_PAD) && wrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if ((pMechanism->mechanism == CKM_RSA_PKCS || pMechanism->mechanism == CKM_RSA_PKCS_OAEP || pMechanism->mechanism == CKM_RSA_AES_KEY_WRAP) &&
		wrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PUBLIC_KEY)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_AES_KEY_WRAP && wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_AES_KEY_WRAP_PAD && wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if ((pMechanism->mechanism == CKM_RSA_PKCS || pMechanism->mechanism == CKM_RSA_PKCS_OAEP || pMechanism->mechanism == CKM_RSA_AES_KEY_WRAP) &&
		wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_RSA)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if ((pMechanism->mechanism == CKM_AES_CBC || pMechanism->mechanism == CKM_AES_CBC_PAD) && wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	// Check if the wrapping key can be used for wrapping
	if (wrapKey->getBooleanValue(CKA_WRAP, false) == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the wrapping key
	if (!isMechanismPermitted(wrapKey, pMechanism->mechanism))
		return CKR_MECHANISM_INVALID;

	// Check the to be wrapped key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_KEY_HANDLE_INVALID;

	CK_BBOOL isKeyOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check user credentials for the to be wrapped key
	rv = haveRead(session->getState(), isKeyOnToken, isKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");

		return rv;
	}

	// Check if the to be wrapped key can be wrapped
	if (key->getBooleanValue(CKA_EXTRACTABLE, false) == false)
		return CKR_KEY_UNEXTRACTABLE;
	if (key->getBooleanValue(CKA_WRAP_WITH_TRUSTED, false) && wrapKey->getBooleanValue(CKA_TRUSTED, false) == false)
		return CKR_KEY_NOT_WRAPPABLE;

	// Check the class
	CK_OBJECT_CLASS keyClass = key->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED);
	if (keyClass != CKO_SECRET_KEY && keyClass != CKO_PRIVATE_KEY)
		return CKR_KEY_NOT_WRAPPABLE;
	// CKM_RSA_PKCS and CKM_RSA_PKCS_OAEP can be used only on SECRET keys: PKCS#11 2.40 draft 2 section 2.1.6 PKCS #1 v1.5 RSA & section 2.1.8 PKCS #1 RSA OAEP
	if ((pMechanism->mechanism == CKM_RSA_PKCS || pMechanism->mechanism == CKM_RSA_PKCS_OAEP) && keyClass != CKO_SECRET_KEY)
		return CKR_KEY_NOT_WRAPPABLE;

	// Verify the wrap template attribute
	if (wrapKey->attributeExists(CKA_WRAP_TEMPLATE))
	{
		OSAttribute attr = wrapKey->getAttribute(CKA_WRAP_TEMPLATE);

		if (attr.isAttributeMapAttribute())
		{
			typedef std::map<CK_ATTRIBUTE_TYPE,OSAttribute> attrmap_type;

			const attrmap_type& map = attr.getAttributeMapValue();

			for (attrmap_type::const_iterator it = map.begin(); it != map.end(); ++it)
			{
				if (!key->attributeExists(it->first))
				{
					return CKR_KEY_NOT_WRAPPABLE;
				}

				OSAttribute keyAttr = key->getAttribute(it->first);
				ByteString v1, v2;
				if (!keyAttr.peekValue(v1) || !it->second.peekValue(v2) || (v1 != v2))
				{
					return CKR_KEY_NOT_WRAPPABLE;
				}
			}
		}
	}

	// Get the key data to encrypt
	ByteString keydata;
	if (keyClass == CKO_SECRET_KEY)
	{
		if (isKeyPrivate)
		{
			bool bOK = token->decrypt(key->getByteStringValue(CKA_VALUE), keydata);
			if (!bOK) return CKR_GENERAL_ERROR;
		}
		else
		{
			keydata = key->getByteStringValue(CKA_VALUE);
		}
	}
	else
	{
		CK_KEY_TYPE keyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);
		AsymAlgo::Type alg = AsymAlgo::Unknown;
		switch (keyType) {
			case CKK_RSA:
				alg = AsymAlgo::RSA;
				break;
#ifdef WITH_ECC
			case CKK_EC:
				// can be ecdh too but it doesn't matter
				alg = AsymAlgo::ECDSA;
				break;
#endif
#ifdef WITH_EDDSA
                        case CKK_EC_EDWARDS:
			        alg = AsymAlgo::EDDSA;
				break;
#endif
			default:
				return CKR_KEY_NOT_WRAPPABLE;
		}
		AsymmetricAlgorithm* asymCrypto = NULL;
		PrivateKey* privateKey = NULL;
		asymCrypto = CryptoFactory::i()->getAsymmetricAlgorithm(alg);
		if (asymCrypto == NULL)
			return CKR_GENERAL_ERROR;
		privateKey = asymCrypto->newPrivateKey();
		if (privateKey == NULL)
		{
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_HOST_MEMORY;
		}
		switch (keyType) {
			case CKK_RSA:
				rv = getRSAPrivateKey((RSAPrivateKey*)privateKey, token, key);
				break;
				break;
				break;
#ifdef WITH_ECC
			case CKK_EC:
				rv = getECPrivateKey((ECPrivateKey*)privateKey, token, key);
				break;
#endif
#ifdef WITH_EDDSA
                        case CKK_EC_EDWARDS:
				rv = getEDPrivateKey((EDPrivateKey*)privateKey, token, key);
				break;
#endif
		}
		if (rv != CKR_OK)
		{
			asymCrypto->recyclePrivateKey(privateKey);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
			return CKR_GENERAL_ERROR;
		}
		keydata = privateKey->PKCS8Encode();
		asymCrypto->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(asymCrypto);
	}
	if (keydata.size() == 0)
		return CKR_KEY_NOT_WRAPPABLE;

	keyClass = wrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED);
	ByteString wrapped;

	if (pMechanism->mechanism == CKM_RSA_AES_KEY_WRAP)
	{
		rv = WrapMechRsaAesKw(hSession, pMechanism, token, wrapKey, keydata, wrapped);
		if (rv != CKR_OK)
		{
			return rv;
		}
	}
	else
	{
		if (keyClass == CKO_SECRET_KEY)
			rv = SoftHSM::WrapKeySym(pMechanism, token, wrapKey, keydata, wrapped);
		else
			rv = SoftHSM::WrapKeyAsym(pMechanism, token, wrapKey, keydata, wrapped);
		if (rv != CKR_OK)
			return rv;
	}

	if (pWrappedKey != NULL) {
		if (*pulWrappedKeyLen >= wrapped.size())
			memcpy(pWrappedKey, wrapped.byte_str(), wrapped.size());
		else
			rv = CKR_BUFFER_TOO_SMALL;
	}

	*pulWrappedKeyLen = wrapped.size();
	return rv;
}

// Internal: Unwrap blob using symmetric key
CK_RV SoftHSM::UnwrapKeySym
(
	CK_MECHANISM_PTR pMechanism,
	ByteString& wrapped,
	Token* token,
	OSObject* unwrapKey,
	ByteString& keydata
)
{
	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymWrap::Type mode = SymWrap::Unknown;
	size_t bb = 8;

	switch(pMechanism->mechanism) {
#ifdef HAVE_AES_KEY_WRAP
		case CKM_AES_KEY_WRAP:
			algo = SymAlgo::AES;
			mode = SymWrap::AES_KEYWRAP;
			break;
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			algo = SymAlgo::AES;
			mode = SymWrap::AES_KEYWRAP_PAD;
			break;
#endif
	        case CKM_AES_CBC_PAD:
			algo = SymAlgo::AES;
			// Block-size validation (multiples of AES_BLOCK_BYTES) was
			// already enforced in C_UnwrapKey before this helper is called.
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	SymmetricKey* unwrappingkey = new SymmetricKey();

	if (getSymmetricKey(unwrappingkey, token, unwrapKey) != CKR_OK)
	{
		cipher->recycleKey(unwrappingkey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}

	// adjust key bit length
	unwrappingkey->setBitLen(unwrappingkey->getKeyBits().size() * bb);

	ByteString iv;
	ByteString decryptedFinal;
	CK_RV rv = CKR_OK;
	
	switch(pMechanism->mechanism) {

	case CKM_AES_CBC_PAD:
	default:
		// Unwrap the key
		rv = CKR_OK;
		if (!cipher->unwrapKey(unwrappingkey, mode, wrapped, keydata))
			rv = CKR_GENERAL_ERROR;
	}

	cipher->recycleKey(unwrappingkey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
	return rv;
}

// Internal: Unwrap blob using asymmetric key
CK_RV SoftHSM::UnwrapKeyAsym
(
	CK_MECHANISM_PTR pMechanism,
	ByteString& wrapped,
	Token* token,
	OSObject* unwrapKey,
	ByteString& keydata
)
{
	CK_RV rv = CKR_OK;
	// Get the symmetric algorithm matching the mechanism
	AsymAlgo::Type algo = AsymAlgo::Unknown;
	AsymMech::Type mode = AsymMech::Unknown;
	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
			algo = AsymAlgo::RSA;
			mode = AsymMech::RSA_PKCS;
			break;

		case CKM_RSA_PKCS_OAEP:
			algo = AsymAlgo::RSA;
			mode = AsymMech::RSA_PKCS_OAEP;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}
	AsymmetricAlgorithm* cipher = CryptoFactory::i()->getAsymmetricAlgorithm(algo);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;

	PrivateKey* unwrappingkey = cipher->newPrivateKey();
	if (unwrappingkey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
		return CKR_HOST_MEMORY;
	}

	switch(pMechanism->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_RSA_PKCS_OAEP:
			if (getRSAPrivateKey((RSAPrivateKey*)unwrappingkey, token, unwrapKey) != CKR_OK)
			{
				cipher->recyclePrivateKey(unwrappingkey);
				CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
				return CKR_GENERAL_ERROR;
			}
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	// Unwrap the key
	if (!cipher->unwrapKey(unwrappingkey, wrapped, keydata, mode))
		rv = CKR_GENERAL_ERROR;
	cipher->recyclePrivateKey(unwrappingkey);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(cipher);
	return rv;
}

// Internal: Unwrap with mechanism RSA_AES_KEY_WRAP
CK_RV SoftHSM::UnwrapMechRsaAesKw
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	Token *token,
	OSObject *unwrapKey,
	ByteString &wrapped,
	ByteString &keydata
)
{
	CK_RV rv = CKR_OK;
	CK_OBJECT_HANDLE hEmphKey = CK_INVALID_HANDLE;
	CK_RSA_AES_KEY_WRAP_PARAMS_PTR params = (CK_RSA_AES_KEY_WRAP_PARAMS_PTR)pMechanism->pParameter;
	ByteString emphkeydata;
	ByteString modulus;
	ByteString modulusValue = unwrapKey->getByteStringValue(CKA_MODULUS);

	CK_BBOOL isUnwrapKeyPrivate = unwrapKey->getBooleanValue(CKA_PRIVATE, true);
	if(isUnwrapKeyPrivate)
	{
		token->decrypt(modulusValue, modulus);
	}
	else
	{
		modulus = modulusValue;
	}

	CK_ULONG ulWrappedKeyLen = wrapped.size();
	CK_ULONG wrappedLen1 = modulus.size();
	if (wrappedLen1 > ulWrappedKeyLen)
		return CKR_WRAPPED_KEY_LEN_RANGE;
	CK_ULONG wrappedLen2 = ulWrappedKeyLen - wrappedLen1;

	ByteString wrapped_1(&wrapped[0], wrappedLen1); // the wrapped AES key
	CK_MECHANISM oaepMech = {CKM_RSA_PKCS_OAEP, params->pOAEPParams, sizeof(CK_RSA_PKCS_OAEP_PARAMS)};

	// Un-wraps the temporary AES key from the first part with the private RSA key using CKM_RSA_PKCS_OAEP.
	rv = UnwrapKeyAsym(&oaepMech, wrapped_1, token, unwrapKey, emphkeydata);
	if (rv != CKR_OK)
	{
		emphkeydata.wipe();
		return rv;
	}

	CK_OBJECT_CLASS emphKeyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE emphKeyType = CKK_AES;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE emph_temp[] = {
		{CKA_CLASS, &emphKeyClass, sizeof(CK_OBJECT_CLASS)},
		{CKA_KEY_TYPE, &emphKeyType, sizeof(CK_KEY_TYPE)},
		{CKA_TOKEN, &bFalse, sizeof(CK_BBOOL)},
		{CKA_PRIVATE, &bTrue, sizeof(CK_BBOOL)},
		{CKA_UNWRAP, &bTrue, sizeof(CK_BBOOL)}
	};

	// Create the temporary AES object using C_CreateObject
	rv = this->CreateObject(hSession, emph_temp, sizeof(emph_temp) / sizeof(CK_ATTRIBUTE), &hEmphKey, OBJECT_OP_UNWRAP);
	if (rv != CKR_OK)
	{
		// Remove secret that may have been created already when the function fails.
		if (hEmphKey != CK_INVALID_HANDLE)
		{
			OSObject *emphKey = (OSObject *)handleManager->getObject(hEmphKey);
			handleManager->destroyObject(hEmphKey);
			if(emphKey) emphKey->destroyObject();
			hEmphKey = CK_INVALID_HANDLE;
		}
		emphkeydata.wipe();
		return rv;
	}

	// Store the attributes of emphkey
	OSObject *emphKey = (OSObject *)handleManager->getObject(hEmphKey);
	if (emphKey == NULL_PTR || !emphKey->isValid())
	{
		rv = CKR_FUNCTION_FAILED;
		handleManager->destroyObject(hEmphKey);
		if(emphKey) emphKey->destroyObject();
		hEmphKey = CK_INVALID_HANDLE;
		emphkeydata.wipe();
		return rv;
	}

	if (emphKey->startTransaction())
	{
		bool bOK = true;
		// Common Attributes
		bOK = bOK && emphKey->setAttribute(CKA_LOCAL, false);
		// Common Secret Key Attributes
		bOK = bOK && emphKey->setAttribute(CKA_ALWAYS_SENSITIVE, false);
		bOK = bOK && emphKey->setAttribute(CKA_NEVER_EXTRACTABLE, false);
		// Secret Attributes
		ByteString emphKeyValue;
		token->encrypt(emphkeydata, emphKeyValue);
		bOK = bOK && emphKey->setAttribute(CKA_VALUE, emphKeyValue);

		if (bOK)
		{
			bOK = emphKey->commitTransaction();
		}
		else
		{
			emphKey->abortTransaction();
		}

		// Zeroizes the temporary AES key.
		emphkeydata.wipe();
		emphKeyValue.wipe();

		if (!bOK)
		{
			rv = CKR_FUNCTION_FAILED;
			handleManager->destroyObject(hEmphKey);
			emphKey->destroyObject();
			hEmphKey = CK_INVALID_HANDLE;
			return rv;
		}
	}
	else
	{
		rv = CKR_FUNCTION_FAILED;
		emphkeydata.wipe();
		handleManager->destroyObject(hEmphKey);
		emphKey->destroyObject();
		hEmphKey = CK_INVALID_HANDLE;
		return rv;
	}

	ByteString wrapped_2(&wrapped[wrappedLen1], wrappedLen2); // the wrapped target key
	CK_MECHANISM emphMech = {CKM_AES_KEY_WRAP_PAD, NULL_PTR, 0};

	// Un-wraps the target key from the second part with the temporary AES key using CKM_AES_KEY_WRAP_PAD (RFC5649)
	rv = UnwrapKeySym(&emphMech, wrapped_2, token, emphKey, keydata);

	// remove the emphkey handle
	handleManager->destroyObject(hEmphKey);
	emphKey->destroyObject();
	hEmphKey = CK_INVALID_HANDLE;

	return rv;
}

// Unwrap the specified key using the specified unwrapping key
CK_RV SoftHSM::C_UnwrapKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hUnwrappingKey,
	CK_BYTE_PTR pWrappedKey,
	CK_ULONG ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR hKey
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pWrappedKey == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (hKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	CK_RV rv;
	// Check the mechanism
	switch(pMechanism->mechanism)
	{
#ifdef HAVE_AES_KEY_WRAP
		case CKM_AES_KEY_WRAP:
			if ((ulWrappedKeyLen < 24) || ((ulWrappedKeyLen % 8) != 0))
				return CKR_WRAPPED_KEY_LEN_RANGE;
			// Does not handle optional init vector
			if (pMechanism->pParameter != NULL_PTR ||
                            pMechanism->ulParameterLen != 0)
				return CKR_ARGUMENTS_BAD;
			break;
#endif
#ifdef HAVE_AES_KEY_WRAP_PAD
		case CKM_AES_KEY_WRAP_PAD:
			if ((ulWrappedKeyLen < 16) || ((ulWrappedKeyLen % 8) != 0))
				return CKR_WRAPPED_KEY_LEN_RANGE;
			// Does not handle optional init vector
			if (pMechanism->pParameter != NULL_PTR ||
                            pMechanism->ulParameterLen != 0)
				return CKR_ARGUMENTS_BAD;
			break;
#endif
		case CKM_RSA_PKCS:
			// Input length checks needs to be done later when unwrapping key is known
			break;
		case CKM_RSA_PKCS_OAEP:
			rv = MechParamCheckRSAPKCSOAEP(pMechanism);
			if (rv != CKR_OK)
				return rv;
			break;
		case CKM_RSA_AES_KEY_WRAP:
			rv = MechParamCheckRSAAESKEYWRAP(pMechanism);
			if (rv != CKR_OK)
				return rv;
			break;

	        case CKM_AES_CBC_PAD:
			// Ciphertext must be a non-empty multiple of the AES block size (16 bytes).
			// PKCS#7 padding means at least one full block is always present.
			if ((ulWrappedKeyLen < 16) || ((ulWrappedKeyLen % 16) != 0))
				return CKR_WRAPPED_KEY_LEN_RANGE;
			// IV is mandatory and must be exactly one AES block (16 bytes).
			if (pMechanism->pParameter == NULL_PTR ||
                            pMechanism->ulParameterLen != 16)
				return CKR_ARGUMENTS_BAD;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the unwrapping key handle.
	OSObject *unwrapKey = (OSObject *)handleManager->getObject(hUnwrappingKey);
	if (unwrapKey == NULL_PTR || !unwrapKey->isValid()) return CKR_UNWRAPPING_KEY_HANDLE_INVALID;

	CK_BBOOL isUnwrapKeyOnToken = unwrapKey->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isUnwrapKeyPrivate = unwrapKey->getBooleanValue(CKA_PRIVATE, true);

	// Check user credentials
	rv = haveRead(session->getState(), isUnwrapKeyOnToken, isUnwrapKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");

		return rv;
	}

	// Check unwrapping key class and type
	if ((pMechanism->mechanism == CKM_AES_KEY_WRAP || pMechanism->mechanism == CKM_AES_KEY_WRAP_PAD) && unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_AES_KEY_WRAP && unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if (pMechanism->mechanism == CKM_AES_KEY_WRAP_PAD && unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if ((pMechanism->mechanism == CKM_RSA_PKCS || pMechanism->mechanism == CKM_RSA_PKCS_OAEP || pMechanism->mechanism == CKM_RSA_AES_KEY_WRAP) &&
		unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PRIVATE_KEY)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if ((pMechanism->mechanism == CKM_RSA_PKCS || pMechanism->mechanism == CKM_RSA_PKCS_OAEP || pMechanism->mechanism == CKM_RSA_AES_KEY_WRAP) &&
		unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_RSA)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if ((pMechanism->mechanism == CKM_AES_CBC || pMechanism->mechanism == CKM_AES_CBC_PAD) && unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	// Check if the unwrapping key can be used for unwrapping
	if (unwrapKey->getBooleanValue(CKA_UNWRAP, false) == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the unwrap key
	if (!isMechanismPermitted(unwrapKey, pMechanism->mechanism))
		return CKR_MECHANISM_INVALID;

	// Extract information from the template that is needed to create the object.
	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
	bool isImplicit = false;
	rv = extractObjectInformation(pTemplate, ulCount, objClass, keyType, dummy, isOnToken, isPrivate, isImplicit);
	if (rv != CKR_OK)
	{
		ERROR_MSG("Mandatory attribute not present in template");
		return rv;
	}

	// Report errors and/or unexpected usage.
	if (objClass != CKO_SECRET_KEY && objClass != CKO_PRIVATE_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	// Key type will be handled at object creation

	// Check authorization
	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}

	// Build unwrapped key template
	const CK_ULONG maxAttribs = 32;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - secretAttribsCount))
		return CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i = 0; i < ulCount; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
				continue;
			default:
				secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	// Apply the unwrap template
	if (unwrapKey->attributeExists(CKA_UNWRAP_TEMPLATE))
	{
		OSAttribute unwrapAttr = unwrapKey->getAttribute(CKA_UNWRAP_TEMPLATE);

		if (unwrapAttr.isAttributeMapAttribute())
		{
			typedef std::map<CK_ATTRIBUTE_TYPE,OSAttribute> attrmap_type;

			const attrmap_type& map = unwrapAttr.getAttributeMapValue();

			for (attrmap_type::const_iterator it = map.begin(); it != map.end(); ++it)
			{
				CK_ATTRIBUTE* attr = NULL;
				for (CK_ULONG i = 0; i < secretAttribsCount; ++i)
				{
					if (it->first == secretAttribs[i].type)
					{
						if (attr != NULL)
						{
							return CKR_TEMPLATE_INCONSISTENT;
						}
						attr = &secretAttribs[i];
						ByteString value;
						it->second.peekValue(value);
						if (attr->ulValueLen != value.size())
						{
							return CKR_TEMPLATE_INCONSISTENT;
						}
						if (memcmp(attr->pValue, value.const_byte_str(), value.size()) != 0)
						{
							return CKR_TEMPLATE_INCONSISTENT;
						}
					}
				}
				if (attr == NULL)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}
			}
		}
	}

	*hKey = CK_INVALID_HANDLE;

	// Unwrap the key
	ByteString wrapped(pWrappedKey, ulWrappedKeyLen);
	ByteString keydata;

	if (pMechanism->mechanism == CKM_RSA_AES_KEY_WRAP)
	{
		rv = UnwrapMechRsaAesKw(hSession, pMechanism, token, unwrapKey, wrapped, keydata);
		if (rv != CKR_OK)
		{
			return rv;
		}
	}
	else
	{
		if (unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) == CKO_SECRET_KEY)
			rv = UnwrapKeySym(pMechanism, wrapped, token, unwrapKey, keydata);
		else if (unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) == CKO_PRIVATE_KEY)
			rv = UnwrapKeyAsym(pMechanism, wrapped, token, unwrapKey, keydata);
		else
			rv = CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
		if (rv != CKR_OK)
			return rv;
	}

	// Create the secret object using C_CreateObject
	rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, hKey, OBJECT_OP_UNWRAP);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*hKey);
		if (osobject == NULL_PTR || !osobject->isValid())
        {
			rv = CKR_FUNCTION_FAILED;
        }
		else if (osobject->startTransaction())
		{
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL, false);

			// Common Secret Key Attributes
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, false);

			// Secret Attributes
			if (objClass == CKO_SECRET_KEY)
			{
				ByteString value;
				if (isPrivate)
					token->encrypt(keydata, value);
				else
					value = keydata;
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			}
			else if (keyType == CKK_RSA)
			{
				bOK = bOK && setRSAPrivateKey(osobject, keydata, token, isPrivate != CK_FALSE);
			}
#ifdef WITH_ECC
			else if (keyType == CKK_EC)
			{
				bOK = bOK && setECPrivateKey(osobject, keydata, token, isPrivate != CK_FALSE);
			}
#endif
#ifdef WITH_EDDSA
			else if (keyType == CKK_EC_EDWARDS)
			{
				bOK = bOK && setEDPrivateKey(osobject, keydata, token, isPrivate != CK_FALSE);
			}
#endif
			else
				bOK = false;

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		}
		else
			rv = CKR_FUNCTION_FAILED;
	}

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*hKey != CK_INVALID_HANDLE)
		{
			OSObject* obj = (OSObject*)handleManager->getObject(*hKey);
			handleManager->destroyObject(*hKey);
			if (obj) obj->destroyObject();
			*hKey = CK_INVALID_HANDLE;
		}

	}

	return rv;
}

// ─────────────────────────────────────────────────────────────────────────────
// G5: PKCS#11 v3.2 authenticated key wrap / unwrap (CKM_AES_GCM only)
//
// Identical to C_WrapKey / C_UnwrapKey except:
//   • an additional pAssociatedData / ulAssociatedDataLen parameter is
//     authenticated (but not encrypted) by the AEAD mechanism
//   • only CKM_AES_GCM is supported (AES-KW does not provide native AAD)
//   • wrapped format: ciphertext ‖ tag  (tag length = ulTagBits/8)
//
// AES secret key wrapping only; private key wrapping is not supported
// (add PKCS8Encode / setXXXPrivateKey paths to extend in future).
// ─────────────────────────────────────────────────────────────────────────────

CK_RV SoftHSM::C_WrapKeyAuthenticated
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hWrappingKey,
	CK_OBJECT_HANDLE hKey,
	CK_BYTE_PTR pAssociatedData,
	CK_ULONG ulAssociatedDataLen,
	CK_BYTE_PTR pWrappedKey,
	CK_ULONG_PTR pulWrappedKeyLen
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pMechanism == NULL_PTR || pulWrappedKeyLen == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pMechanism->mechanism != CKM_AES_GCM) return CKR_MECHANISM_INVALID;
	if (pMechanism->pParameter == NULL_PTR ||
	    pMechanism->ulParameterLen != sizeof(CK_AES_GCM_PARAMS))
		return CKR_ARGUMENTS_BAD;
	CK_AES_GCM_PARAMS* gcmParam = reinterpret_cast<CK_AES_GCM_PARAMS*>(pMechanism->pParameter);
	if (gcmParam->pIv == NULL_PTR || gcmParam->ulIvLen == 0) return CKR_ARGUMENTS_BAD;
	size_t tagLen = gcmParam->ulTagBits / 8;
	if (tagLen == 0 || tagLen > 16) return CKR_ARGUMENTS_BAD;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Validate wrapping key
	OSObject* wrapKey = (OSObject*)handleManager->getObject(hWrappingKey);
	if (wrapKey == NULL_PTR || !wrapKey->isValid()) return CKR_WRAPPING_KEY_HANDLE_INVALID;
	if (wrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if (wrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
	if (wrapKey->getBooleanValue(CKA_WRAP, false) == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	{
		CK_BBOOL onTok = wrapKey->getBooleanValue(CKA_TOKEN, false);
		CK_BBOOL priv  = wrapKey->getBooleanValue(CKA_PRIVATE, true);
		CK_RV rv2 = haveRead(session->getState(), onTok, priv);
		if (rv2 != CKR_OK) return rv2;
	}

	// Validate key-to-be-wrapped
	OSObject* key = (OSObject*)handleManager->getObject(hKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_KEY_HANDLE_INVALID;
	if (key->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
		return CKR_KEY_NOT_WRAPPABLE; // private-key PKCS8 wrapping not yet implemented
	if (key->getBooleanValue(CKA_EXTRACTABLE, false) == false) return CKR_KEY_UNEXTRACTABLE;
	if (key->getBooleanValue(CKA_WRAP_WITH_TRUSTED, false) &&
	    wrapKey->getBooleanValue(CKA_TRUSTED, false) == false)
		return CKR_KEY_NOT_WRAPPABLE;
	{
		CK_BBOOL onTok = key->getBooleanValue(CKA_TOKEN, false);
		CK_BBOOL priv  = key->getBooleanValue(CKA_PRIVATE, true);
		CK_RV rv2 = haveRead(session->getState(), onTok, priv);
		if (rv2 != CKR_OK) return rv2;
	}

	// Extract raw key bytes
	ByteString keydata;
	{
		CK_BBOOL isPriv = key->getBooleanValue(CKA_PRIVATE, true);
		if (isPriv)
		{
			if (!token->decrypt(key->getByteStringValue(CKA_VALUE), keydata))
				return CKR_GENERAL_ERROR;
		}
		else
		{
			keydata = key->getByteStringValue(CKA_VALUE);
		}
	}
	if (keydata.size() == 0) return CKR_KEY_NOT_WRAPPABLE;

	// Size-query path: return output length without performing crypto.
	if (pWrappedKey == NULL_PTR)
	{
		*pulWrappedKeyLen = static_cast<CK_ULONG>(keydata.size() + tagLen);
		keydata.wipe();
		return CKR_OK;
	}

	// Load the AES wrapping key
	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);
	if (cipher == NULL) { keydata.wipe(); return CKR_MECHANISM_INVALID; }
	SymmetricKey* aesKey = new SymmetricKey();
	if (getSymmetricKey(aesKey, token, wrapKey) != CKR_OK)
	{
		keydata.wipe();
		cipher->recycleKey(aesKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}
	aesKey->setBitLen(aesKey->getKeyBits().size() * 8);

	// AES-GCM encrypt: ciphertext || tag
	// padding=false, counterBits=0 for GCM; tag length passed as tagBytes (7th arg).
	ByteString iv(gcmParam->pIv, gcmParam->ulIvLen);
	ByteString aad;
	if (pAssociatedData != NULL_PTR && ulAssociatedDataLen > 0)
		aad = ByteString(pAssociatedData, ulAssociatedDataLen);

	if (!cipher->encryptInit(aesKey, SymMode::GCM, iv, false, 0, aad, tagLen))
	{
		keydata.wipe();
		cipher->recycleKey(aesKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	ByteString cipherOut, tagOut;
	bool ok = cipher->encryptUpdate(keydata, cipherOut) && cipher->encryptFinal(tagOut);
	keydata.wipe();  // clear plaintext key material regardless of outcome
	cipher->recycleKey(aesKey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
	if (!ok) return CKR_FUNCTION_FAILED;

	ByteString wrapped = cipherOut + tagOut;
	if (*pulWrappedKeyLen < wrapped.size()) return CKR_BUFFER_TOO_SMALL;
	memcpy(pWrappedKey, wrapped.byte_str(), wrapped.size());
	*pulWrappedKeyLen = static_cast<CK_ULONG>(wrapped.size());
	return CKR_OK;
}

CK_RV SoftHSM::C_UnwrapKeyAuthenticated
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hUnwrappingKey,
	CK_BYTE_PTR pWrappedKey,
	CK_ULONG ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulAttributeCount,
	CK_BYTE_PTR pAssociatedData,
	CK_ULONG ulAssociatedDataLen,
	CK_OBJECT_HANDLE_PTR phKey
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pWrappedKey == NULL_PTR || phKey == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pTemplate == NULL_PTR && ulAttributeCount != 0) return CKR_ARGUMENTS_BAD;
	if (pMechanism->mechanism != CKM_AES_GCM) return CKR_MECHANISM_INVALID;
	if (pMechanism->pParameter == NULL_PTR ||
	    pMechanism->ulParameterLen != sizeof(CK_AES_GCM_PARAMS))
		return CKR_ARGUMENTS_BAD;
	CK_AES_GCM_PARAMS* gcmParam = reinterpret_cast<CK_AES_GCM_PARAMS*>(pMechanism->pParameter);
	if (gcmParam->pIv == NULL_PTR || gcmParam->ulIvLen == 0) return CKR_ARGUMENTS_BAD;
	size_t tagLen = gcmParam->ulTagBits / 8;
	if (tagLen == 0 || tagLen > 16) return CKR_ARGUMENTS_BAD;
	if (ulWrappedKeyLen <= tagLen) return CKR_WRAPPED_KEY_LEN_RANGE;

	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Validate unwrapping key
	OSObject* unwrapKey = (OSObject*)handleManager->getObject(hUnwrappingKey);
	if (unwrapKey == NULL_PTR || !unwrapKey->isValid()) return CKR_UNWRAPPING_KEY_HANDLE_INVALID;
	if (unwrapKey->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if (unwrapKey->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) != CKK_AES)
		return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
	if (unwrapKey->getBooleanValue(CKA_UNWRAP, false) == false)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	{
		CK_BBOOL onTok = unwrapKey->getBooleanValue(CKA_TOKEN, false);
		CK_BBOOL priv  = unwrapKey->getBooleanValue(CKA_PRIVATE, true);
		CK_RV rv2 = haveRead(session->getState(), onTok, priv);
		if (rv2 != CKR_OK) return rv2;
	}

	// Parse template to determine destination object class
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummyCert;
	bool isImplicit = false;
	{
		CK_RV rv2 = extractObjectInformation(pTemplate, ulAttributeCount,
		                                      objClass, keyType, dummyCert,
		                                      isOnToken, isPrivate, isImplicit);
		if (rv2 != CKR_OK) return rv2;
	}
	if (objClass != CKO_SECRET_KEY) return CKR_ATTRIBUTE_VALUE_INVALID; // private-key not yet supported

	// Authorization check for creating the new object
	{
		CK_RV rv2 = haveWrite(session->getState(), isOnToken, isPrivate);
		if (rv2 != CKR_OK) return rv2;
	}

	// Load the AES unwrapping key
	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);
	if (cipher == NULL) return CKR_MECHANISM_INVALID;
	SymmetricKey* aesKey = new SymmetricKey();
	if (getSymmetricKey(aesKey, token, unwrapKey) != CKR_OK)
	{
		cipher->recycleKey(aesKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_GENERAL_ERROR;
	}
	aesKey->setBitLen(aesKey->getKeyBits().size() * 8);

	// AES-GCM decrypt: pWrappedKey = ciphertext ‖ tag
	ByteString iv(gcmParam->pIv, gcmParam->ulIvLen);
	ByteString aad;
	if (pAssociatedData != NULL_PTR && ulAssociatedDataLen > 0)
		aad = ByteString(pAssociatedData, ulAssociatedDataLen);

	// padding=false, counterBits=0 for GCM; tag length passed as tagBytes (7th arg).
	if (!cipher->decryptInit(aesKey, SymMode::GCM, iv, false, 0, aad, tagLen))
	{
		cipher->recycleKey(aesKey);
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return CKR_MECHANISM_INVALID;
	}

	// Pass ciphertext ‖ tag as a single buffer (OSSL AEAD layer splits internally)
	ByteString aeadBuf(pWrappedKey, ulWrappedKeyLen);
	ByteString keydata, discarded;
	bool ok = cipher->decryptUpdate(aeadBuf, keydata) && cipher->decryptFinal(discarded);
	cipher->recycleKey(aesKey);
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
	if (!ok) { keydata.wipe(); return CKR_WRAPPED_KEY_INVALID; } // auth tag mismatch

	// Build the secret-key creation template (mirrors C_UnwrapKey pattern)
	const CK_ULONG maxAttribs = 32;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS,    &objClass,  sizeof(objClass)  },
		{ CKA_TOKEN,    &isOnToken, sizeof(isOnToken)  },
		{ CKA_PRIVATE,  &isPrivate, sizeof(isPrivate)  },
		{ CKA_KEY_TYPE, &keyType,   sizeof(keyType)    }
	};
	CK_ULONG secretAttribsCount = 4;
	if (ulAttributeCount > (maxAttribs - secretAttribsCount))
	{
		keydata.wipe(); // plaintext key material must be zeroed before early return
		return CKR_TEMPLATE_INCONSISTENT;
	}
	for (CK_ULONG i = 0; i < ulAttributeCount; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS: case CKA_TOKEN: case CKA_PRIVATE: case CKA_KEY_TYPE:
				continue;
			default:
				secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	*phKey = CK_INVALID_HANDLE;
	CK_RV rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_UNWRAP);
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid())
		{
			rv = CKR_FUNCTION_FAILED;
		}
		else if (osobject->startTransaction())
		{
			bool bOK = true;
			bOK = bOK && osobject->setAttribute(CKA_LOCAL, false);
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, false);
			ByteString value;
			if (isPrivate)
				token->encrypt(keydata, value);
			else
				value = keydata;
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			value.wipe();  // clear encrypted/plaintext value copy
			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();
			if (!bOK) rv = CKR_FUNCTION_FAILED;
		}
		else
		{
			rv = CKR_FUNCTION_FAILED;
		}
	}
	keydata.wipe();  // clear decrypted plaintext key material

	if (rv != CKR_OK && *phKey != CK_INVALID_HANDLE)
	{
		OSObject* obj = (OSObject*)handleManager->getObject(*phKey);
		handleManager->destroyObject(*phKey);
		if (obj) obj->destroyObject();
		*phKey = CK_INVALID_HANDLE;
	}
	return rv;
}

// Derive a key from the specified base key
CK_RV SoftHSM::C_DeriveKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey
)
{
	if (!isInitialised) return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (pTemplate == NULL_PTR) return CKR_ARGUMENTS_BAD;
	if (phKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL) return CKR_SESSION_HANDLE_INVALID;

	// Check the mechanism, only accept DH and ECDH derive
	switch (pMechanism->mechanism)
	{
		case CKM_ECDH1_DERIVE:
#endif
		case CKM_AES_ECB_ENCRYPT_DATA:
		case CKM_AES_CBC_ENCRYPT_DATA:
		case CKM_CONCATENATE_DATA_AND_BASE:
		case CKM_CONCATENATE_BASE_AND_DATA:
		case CKM_CONCATENATE_BASE_AND_KEY:
			break;

		default:
			ERROR_MSG("Invalid mechanism");
			return CKR_MECHANISM_INVALID;
	}

	// Get the token
	Token* token = session->getToken();
	if (token == NULL) return CKR_GENERAL_ERROR;

	// Check the key handle.
	OSObject *key = (OSObject *)handleManager->getObject(hBaseKey);
	if (key == NULL_PTR || !key->isValid()) return CKR_OBJECT_HANDLE_INVALID;

	CK_BBOOL isKeyOnToken = key->getBooleanValue(CKA_TOKEN, false);
	CK_BBOOL isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, true);

	// Check user credentials
	CK_RV rv = haveRead(session->getState(), isKeyOnToken, isKeyPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");

		return rv;
	}

	// Check if key can be used for derive
	if (!key->getBooleanValue(CKA_DERIVE, false))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	// Check if the specified mechanism is allowed for the key
	if (!isMechanismPermitted(key, pMechanism->mechanism))
		return CKR_MECHANISM_INVALID;

	// Extract information from the template that is needed to create the object.
	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	CK_BBOOL isOnToken = CK_FALSE;
	CK_BBOOL isPrivate = CK_TRUE;
	CK_CERTIFICATE_TYPE dummy;
    bool isImplicit = pMechanism->mechanism == CKM_CONCATENATE_DATA_AND_BASE ||
			pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_DATA ||
			pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_KEY;
    if (isImplicit) {
        // PKCS#11 2.40 section 2.31.5: if no key type is provided then the key produced by this mechanism will
        // be a generic secret key
        objClass = CKO_SECRET_KEY;
        keyType = CKK_GENERIC_SECRET;
    }
    rv = extractObjectInformation(pTemplate, ulCount, objClass, keyType, dummy, isOnToken, isPrivate, isImplicit);
    if (rv != CKR_OK) {
        ERROR_MSG("Mandatory attribute not present in template");
        return rv;
    }

	// Report errors and/or unexpected usage.
	if (objClass != CKO_SECRET_KEY)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	if (keyType != CKK_GENERIC_SECRET &&
	    keyType != CKK_AES)
		return CKR_TEMPLATE_INCONSISTENT;

	// Check authorization
	rv = haveWrite(session->getState(), isOnToken, isPrivate);
	if (rv != CKR_OK)
	{
		if (rv == CKR_USER_NOT_LOGGED_IN)
			INFO_MSG("User is not authorized");
		if (rv == CKR_SESSION_READ_ONLY)
			INFO_MSG("Session is read-only");

		return rv;
	}


#if defined(WITH_ECC) || defined(WITH_EDDSA)
	// Derive ECDH secret
	if (pMechanism->mechanism == CKM_ECDH1_DERIVE)
	{
		// Check key class and type
		if (key->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_PRIVATE_KEY)
			return CKR_KEY_TYPE_INCONSISTENT;
#ifdef WITH_ECC
		else if (key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) == CKK_EC)
			return this->deriveECDH(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey, keyType, isOnToken, isPrivate);
#endif
#ifdef WITH_EDDSA
		else if (key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) == CKK_EC_EDWARDS ||
		         key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED) == CKK_EC_MONTGOMERY)
			return this->deriveEDDSA(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey, keyType, isOnToken, isPrivate);
#endif
		else
			return CKR_KEY_TYPE_INCONSISTENT;
	}
#endif

	// Derive symmetric secret
	if (pMechanism->mechanism == CKM_AES_ECB_ENCRYPT_DATA ||
	    pMechanism->mechanism == CKM_AES_CBC_ENCRYPT_DATA ||
	    pMechanism->mechanism == CKM_CONCATENATE_DATA_AND_BASE ||
	    pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_DATA ||
	    pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_KEY)
	{
		// Check key class and type
		CK_KEY_TYPE baseKeyType = key->getUnsignedLongValue(CKA_KEY_TYPE, CKK_VENDOR_DEFINED);
		if (key->getUnsignedLongValue(CKA_CLASS, CKO_VENDOR_DEFINED) != CKO_SECRET_KEY)
			return CKR_KEY_TYPE_INCONSISTENT;
		if (pMechanism->mechanism == CKM_AES_ECB_ENCRYPT_DATA &&
		    baseKeyType != CKK_AES)
			return CKR_KEY_TYPE_INCONSISTENT;
		if (pMechanism->mechanism == CKM_AES_CBC_ENCRYPT_DATA &&
		    baseKeyType != CKK_AES)
			return CKR_KEY_TYPE_INCONSISTENT;

		return this->deriveSymmetric(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey, keyType, isOnToken, isPrivate);
	}

	return CKR_MECHANISM_INVALID;
}

CK_RV SoftHSM::generateGeneric
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t keyLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				keyLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// CKA_VALUE_LEN must be specified
	if (keyLen == 0)
	{
		INFO_MSG("Missing CKA_VALUE_LEN in pTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Check keyLen
	if (keyLen < 1 || keyLen > MAX_GENERIC_KEY_LEN_BYTES)
	{
		INFO_MSG("bad generic key length");
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Generate the secret key
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL) return CKR_GENERAL_ERROR;
	ByteString key;
	if (!rng->generateRandom(key, keyLen)) return CKR_GENERAL_ERROR;

        CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
			default:
				keyAttribs[keyAttribsCount++] = pTemplate[i];
				break;
		}
	}

	if (rv == CKR_OK)
		rv = CreateObject(hSession, keyAttribs, keyAttribsCount, phKey, OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_GENERIC_SECRET_KEY_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

			// Generic Secret Key Attributes
			ByteString value;
			ByteString kcv;
			SymmetricKey symKey;
			symKey.setKeyBits(key);
			symKey.setBitLen(keyLen);
			if (isPrivate)
			{
				token->encrypt(symKey.getKeyBits(), value);
				token->encrypt(symKey.getKeyCheckValue(), kcv);
			}
			else
			{
				value = symKey.getKeyBits();
				kcv = symKey.getKeyCheckValue();
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	// Remove the key that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* oskey = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (oskey) oskey->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate an AES secret key
CK_RV SoftHSM::generateAES
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t keyLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				keyLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// CKA_VALUE_LEN must be specified
	if (keyLen == 0)
	{
		INFO_MSG("Missing CKA_VALUE_LEN in pTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// keyLen must be 16, 24, or 32
	if (keyLen != AES_KEY_BYTES_128 && keyLen != AES_KEY_BYTES_192 && keyLen != AES_KEY_BYTES_256)
	{
		INFO_MSG("bad AES key length");
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Generate the secret key
	AESKey* key = new AESKey(keyLen * 8);
	SymmetricAlgorithm* aes = CryptoFactory::i()->getSymmetricAlgorithm(SymAlgo::AES);
	if (aes == NULL)
	{
		ERROR_MSG("Could not get SymmetricAlgorithm");
		delete key;
		return CKR_GENERAL_ERROR;
	}
	RNG* rng = CryptoFactory::i()->getRNG();
	if (rng == NULL)
	{
		ERROR_MSG("Could not get RNG");
		aes->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(aes);
		return CKR_GENERAL_ERROR;
	}
	if (!aes->generateKey(*key, rng))
	{
		ERROR_MSG("Could not generate AES secret key");
		aes->recycleKey(key);
		CryptoFactory::i()->recycleSymmetricAlgorithm(aes);
		return CKR_GENERAL_ERROR;
	}

	CK_RV rv = CKR_OK;

	// Create the secret key object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_ATTRIBUTE keyAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG keyAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - keyAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
		default:
			keyAttribs[keyAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, keyAttribs, keyAttribsCount, phKey,OBJECT_OP_GENERATE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) 
        {
			rv = CKR_FUNCTION_FAILED;
		} 
        else if (osobject->startTransaction()) 
        {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
			CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_AES_KEY_GEN;
			bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

			// Common Secret Key Attributes
			bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
			bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
			bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

			// AES Secret Key Attributes
			ByteString value;
			ByteString kcv;
			if (isPrivate)
			{
				token->encrypt(key->getKeyBits(), value);
				token->encrypt(key->getKeyCheckValue(), kcv);
			}
			else
			{
				value = key->getKeyBits();
				kcv = key->getKeyCheckValue();
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	aes->recycleKey(key);
	CryptoFactory::i()->recycleSymmetricAlgorithm(aes);

	// Remove the key that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* oskey = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (oskey) oskey->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}

// Generate a DES secret key

// Generate a DES2 secret key

// Generate a DES3 secret key

// Generate an RSA key pair
CK_RV SoftHSM::generateRSA
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate
)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information: bitlen and public exponent
	size_t bitLen = 0;
	ByteString exponent("010001");
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_MODULUS_BITS:
				if (pPublicKeyTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_MODULUS_BITS does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				bitLen = *(CK_ULONG*)pPublicKeyTemplate[i].pValue;
				break;
			case CKA_PUBLIC_EXPONENT:
				exponent = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// CKA_MODULUS_BITS must be specified to be able to generate a key pair.
	if (bitLen == 0) {
		INFO_MSG("Missing CKA_MODULUS_BITS in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	RSAParameters p;
	p.setE(exponent);
	p.setBitLength(bitLen);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* rsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
	if (rsa == NULL)
		return CKR_GENERAL_ERROR;
	if (!rsa->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
		return CKR_GENERAL_ERROR;
	}

	RSAPublicKey* pub = (RSAPublicKey*) kp->getPublicKey();
	RSAPrivateKey* priv = (RSAPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_RSA;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
				case CKA_PUBLIC_EXPONENT:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_RSA_PKCS_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// RSA Public Key Attributes
				ByteString modulus;
				ByteString publicExponent;
				if (isPublicKeyPrivate)
				{
					token->encrypt(pub->getN(), modulus);
					token->encrypt(pub->getE(), publicExponent);
				}
				else
				{
					modulus = pub->getN();
					publicExponent = pub->getE();
				}
				bOK = bOK && osobject->setAttribute(CKA_MODULUS, modulus);
				bOK = bOK && osobject->setAttribute(CKA_PUBLIC_EXPONENT, publicExponent);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_RSA;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_RSA_PKCS_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// RSA Private Key Attributes
				ByteString modulus;
				ByteString publicExponent;
				ByteString privateExponent;
				ByteString prime1;
				ByteString prime2;
				ByteString exponent1;
				ByteString exponent2;
				ByteString coefficient;
				if (isPrivateKeyPrivate)
				{
					token->encrypt(priv->getN(), modulus);
					token->encrypt(priv->getE(), publicExponent);
					token->encrypt(priv->getD(), privateExponent);
					token->encrypt(priv->getP(), prime1);
					token->encrypt(priv->getQ(), prime2);
					token->encrypt(priv->getDP1(), exponent1);
					token->encrypt(priv->getDQ1(), exponent2);
					token->encrypt(priv->getPQ(), coefficient);
				}
				else
				{
					modulus = priv->getN();
					publicExponent = priv->getE();
					privateExponent = priv->getD();
					prime1 = priv->getP();
					prime2 = priv->getQ();
					exponent1 =  priv->getDP1();
					exponent2 = priv->getDQ1();
					coefficient = priv->getPQ();
				}
				bOK = bOK && osobject->setAttribute(CKA_MODULUS, modulus);
				bOK = bOK && osobject->setAttribute(CKA_PUBLIC_EXPONENT, publicExponent);
				bOK = bOK && osobject->setAttribute(CKA_PRIVATE_EXPONENT, privateExponent);
				bOK = bOK && osobject->setAttribute(CKA_PRIME_1, prime1);
				bOK = bOK && osobject->setAttribute(CKA_PRIME_2, prime2);
				bOK = bOK && osobject->setAttribute(CKA_EXPONENT_1,exponent1);
				bOK = bOK && osobject->setAttribute(CKA_EXPONENT_2, exponent2);
				bOK = bOK && osobject->setAttribute(CKA_COEFFICIENT, coefficient);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	cleanupKeyPair(rsa, kp, NULL, phPublicKey, phPrivateKey, rv);

	return rv;
}


CK_RV SoftHSM::generateEC
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information
	ByteString params;
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_EC_PARAMS:
				params = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (params.size() == 0) {
		INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Set the parameters
	ECParameters p;
	p.setEC(params);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* ec = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
	if (ec == NULL) return CKR_GENERAL_ERROR;
	if (!ec->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ec);
		return CKR_GENERAL_ERROR;
	}

	ECPublicKey* pub = (ECPublicKey*) kp->getPublicKey();
	ECPrivateKey* priv = (ECPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_EC;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// EC Public Key Attributes
				ByteString point;
				if (isPublicKeyPrivate)
				{
					token->encrypt(pub->getQ(), point);
				}
				else
				{
					point = pub->getQ();
				}
				bOK = bOK && osobject->setAttribute(CKA_EC_POINT, point);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_EC;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_EC_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,ulKeyGenMechanism);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// EC Private Key Attributes
				ByteString group;
				ByteString value;
				if (isPrivateKeyPrivate)
				{
					token->encrypt(priv->getEC(), group);
					token->encrypt(priv->getD(), value);
				}
				else
				{
					group = priv->getEC();
					value = priv->getD();
				}
				bOK = bOK && osobject->setAttribute(CKA_EC_PARAMS, group);
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	cleanupKeyPair(ec, kp, NULL, phPublicKey, phPrivateKey, rv);

	return rv;
}

// Generate an EDDSA key pair
CK_RV SoftHSM::generateED
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information
	ByteString params;
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		switch (pPublicKeyTemplate[i].type)
		{
			case CKA_EC_PARAMS:
				params = ByteString((unsigned char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
				break;
			default:
				break;
		}
	}

	// The parameters must be specified to be able to generate a key pair.
	if (params.size() == 0) {
		INFO_MSG("Missing parameter(s) in pPublicKeyTemplate");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// Determine the key type from the public key template (Edwards vs Montgomery)
	CK_KEY_TYPE edKeyType = CKK_EC_EDWARDS;
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		if (pPublicKeyTemplate[i].type == CKA_KEY_TYPE)
		{
			edKeyType = *(CK_KEY_TYPE*)pPublicKeyTemplate[i].pValue;
			break;
		}
	}
	CK_ULONG edKeyGenMech = (edKeyType == CKK_EC_MONTGOMERY)
		? (CK_ULONG)CKM_EC_MONTGOMERY_KEY_PAIR_GEN
		: (CK_ULONG)CKM_EC_EDWARDS_KEY_PAIR_GEN;

	// Set the parameters
	ECParameters p;
	p.setEC(params);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* ec = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
	if (ec == NULL) return CKR_GENERAL_ERROR;
	if (!ec->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ec);
		return CKR_GENERAL_ERROR;
	}

	EDPublicKey* pub = (EDPublicKey*) kp->getPublicKey();
	EDPrivateKey* priv = (EDPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = edKeyType;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		// Add the additional
		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,publicKeyAttribs,publicKeyAttribsCount,phPublicKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,edKeyGenMech);

				// EDDSA / Montgomery Public Key Attributes
				ByteString value;
				if (isPublicKeyPrivate)
				{
					token->encrypt(pub->getA(), value);
				}
				else
				{
					value = pub->getA();
				}
				bOK = bOK && osobject->setAttribute(CKA_EC_POINT, value);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = edKeyType;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i=0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession,privateKeyAttribs,privateKeyAttribsCount,phPrivateKey,OBJECT_OP_GENERATE);

		// Store the attributes that are being supplied by the key generation to the object
		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				// Common Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_LOCAL,true);
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM,edKeyGenMech);

				// Common Private Key Attributes
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// EDDSA / Montgomery Private Key Attributes
				ByteString group;
				ByteString value;
				if (isPrivateKeyPrivate)
				{
					token->encrypt(priv->getEC(), group);
					token->encrypt(priv->getK(), value);
				}
				else
				{
					group = priv->getEC();
					value = priv->getK();
				}
				bOK = bOK && osobject->setAttribute(CKA_EC_PARAMS, group);
				bOK = bOK && osobject->setAttribute(CKA_VALUE, value);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	cleanupKeyPair(ec, kp, NULL, phPublicKey, phPrivateKey, rv);

	return rv;
}

// Generate an ML-DSA key pair (FIPS 204, PKCS#11 v3.2)

CK_RV SoftHSM::generateMLDSA
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information: CKA_PARAMETER_SET selects the ML-DSA variant
	CK_ULONG parameterSet = CKP_ML_DSA_44;  // default
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		if (pPublicKeyTemplate[i].type == CKA_PARAMETER_SET && pPublicKeyTemplate[i].ulValueLen == sizeof(CK_ULONG))
		{
			parameterSet = *(CK_ULONG*)pPublicKeyTemplate[i].pValue;
			break;
		}
	}

	// Set the parameters
	MLDSAParameters p;
	p.setParameterSet(parameterSet);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* mldsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLDSA);
	if (mldsa == NULL) return CKR_GENERAL_ERROR;
	if (!mldsa->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate ML-DSA key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
		return CKR_GENERAL_ERROR;
	}

	MLDSAPublicKey* pub = (MLDSAPublicKey*) kp->getPublicKey();
	MLDSAPrivateKey* priv = (MLDSAPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_ML_DSA;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession, publicKeyAttribs, publicKeyAttribsCount, phPublicKey, OBJECT_OP_GENERATE);

		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				bOK = bOK && osobject->setAttribute(CKA_LOCAL, true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_ML_DSA_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM, ulKeyGenMechanism);

				// ML-DSA Public Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_PARAMETER_SET, (unsigned long)pub->getParameterSet());
				ByteString pubValue;
				if (isPublicKeyPrivate)
					token->encrypt(pub->getValue(), pubValue);
				else
					pubValue = pub->getValue();
				bOK = bOK && osobject->setAttribute(CKA_VALUE, pubValue);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_ML_DSA;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
				case CKA_PARAMETER_SET: // ck4: set directly after CreateObject
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession, privateKeyAttribs, privateKeyAttribsCount, phPrivateKey, OBJECT_OP_GENERATE);

		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				bOK = bOK && osobject->setAttribute(CKA_LOCAL, true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_ML_DSA_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM, ulKeyGenMechanism);

				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// ML-DSA Private Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_PARAMETER_SET, (unsigned long)priv->getParameterSet());
				ByteString privValue;
				if (isPrivateKeyPrivate)
					token->encrypt(priv->getValue(), privValue);
				else
					privValue = priv->getValue();
				bOK = bOK && osobject->setAttribute(CKA_VALUE, privValue);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	cleanupKeyPair(mldsa, kp, NULL, phPublicKey, phPrivateKey, rv);

	return rv;
}

// Generate an SLH-DSA key pair (FIPS 205, PKCS#11 v3.2)

CK_RV SoftHSM::generateSLHDSA
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information: CKA_PARAMETER_SET selects the SLH-DSA variant
	CK_ULONG parameterSet = CKP_SLH_DSA_SHA2_128S;  // default
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		if (pPublicKeyTemplate[i].type == CKA_PARAMETER_SET && pPublicKeyTemplate[i].ulValueLen == sizeof(CK_ULONG))
		{
			parameterSet = *(CK_ULONG*)pPublicKeyTemplate[i].pValue;
			break;
		}
	}

	// Set the parameters
	SLHDSAParameters p;
	p.setParameterSet(parameterSet);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* slhdsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::SLHDSA);
	if (slhdsa == NULL) return CKR_GENERAL_ERROR;
	if (!slhdsa->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate SLH-DSA key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
		return CKR_GENERAL_ERROR;
	}

	SLHDSAPublicKey* pub = (SLHDSAPublicKey*) kp->getPublicKey();
	SLHDSAPrivateKey* priv = (SLHDSAPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_SLH_DSA;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession, publicKeyAttribs, publicKeyAttribsCount, phPublicKey, OBJECT_OP_GENERATE);

		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				bOK = bOK && osobject->setAttribute(CKA_LOCAL, true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_SLH_DSA_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM, ulKeyGenMechanism);

				// SLH-DSA Public Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_PARAMETER_SET, (unsigned long)pub->getParameterSet());
				ByteString pubValue;
				if (isPublicKeyPrivate)
					token->encrypt(pub->getValue(), pubValue);
				else
					pubValue = pub->getValue();
				bOK = bOK && osobject->setAttribute(CKA_VALUE, pubValue);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_SLH_DSA;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
				case CKA_PARAMETER_SET: // ck4: set directly after CreateObject
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession, privateKeyAttribs, privateKeyAttribsCount, phPrivateKey, OBJECT_OP_GENERATE);

		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				bOK = bOK && osobject->setAttribute(CKA_LOCAL, true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_SLH_DSA_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM, ulKeyGenMechanism);

				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// SLH-DSA Private Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_PARAMETER_SET, (unsigned long)priv->getParameterSet());
				ByteString privValue;
				if (isPrivateKeyPrivate)
					token->encrypt(priv->getValue(), privValue);
				else
					privValue = priv->getValue();
				bOK = bOK && osobject->setAttribute(CKA_VALUE, privValue);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	cleanupKeyPair(slhdsa, kp, NULL, phPublicKey, phPrivateKey, rv);

	return rv;
}

// Generate a DH key pair

CK_RV SoftHSM::deriveECDH
(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_KEY_TYPE keyType,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	if ((pMechanism->pParameter == NULL_PTR) ||
	    (pMechanism->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS)))
	{
		DEBUG_MSG("pParameter must be of type CK_ECDH1_DERIVE_PARAMS");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->kdf != CKD_NULL)
	{
		DEBUG_MSG("kdf must be CKD_NULL");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if ((CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulSharedDataLen != 0) ||
	    (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pSharedData != NULL_PTR))
	{
		DEBUG_MSG("there must be no shared data");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if ((CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen == 0) ||
	    (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pPublicData == NULL_PTR))
	{
		DEBUG_MSG("there must be a public data");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t byteLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE:
				INFO_MSG("CKA_VALUE must not be included");
				return CKR_ATTRIBUTE_READ_ONLY;
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				byteLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// Check the length
	// byteLen == 0 impiles return max size the ECC can derive
	switch (keyType)
	{
		case CKK_GENERIC_SECRET:
			break;
#ifndef WITH_FIPS
		case CKK_DES:
			if (byteLen != 0 && byteLen != 8)
			{
				INFO_MSG("CKA_VALUE_LEN must be 0 or 8");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			byteLen = 8;
			break;
#endif
		case CKK_DES2:
			if (byteLen != 0 && byteLen != 16)
			{
				INFO_MSG("CKA_VALUE_LEN must be 0 or 16");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			byteLen = 16;
			break;
		case CKK_DES3:
			if (byteLen != 0 && byteLen != 24)
			{
				INFO_MSG("CKA_VALUE_LEN must be 0 or 24");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			byteLen = 24;
			break;
		case CKK_AES:
			if (byteLen != 0 && byteLen != 16 && byteLen != 24 && byteLen != 32)
			{
				INFO_MSG("CKA_VALUE_LEN must be 0, 16, 24, or 32");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Get the base key handle
	OSObject *baseKey = (OSObject *)handleManager->getObject(hBaseKey);
	if (baseKey == NULL || !baseKey->isValid())
		return CKR_KEY_HANDLE_INVALID;

	// Get the ECDH algorithm handler
	AsymmetricAlgorithm* ecdh = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDH);
	if (ecdh == NULL)
		return CKR_MECHANISM_INVALID;

	// Get the keys
	PrivateKey* privateKey = ecdh->newPrivateKey();
	if (privateKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_HOST_MEMORY;
	}
	if (getECPrivateKey((ECPrivateKey*)privateKey, token, baseKey) != CKR_OK)
	{
		ecdh->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_GENERAL_ERROR;
	}

	ByteString publicData;
	publicData.resize(CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen);
	memcpy(&publicData[0],
	       CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pPublicData,
	       CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen);
	PublicKey* publicKey = ecdh->newPublicKey();
	if (publicKey == NULL)
	{
		ecdh->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_HOST_MEMORY;
	}
	if (getECDHPublicKey((ECPublicKey*)publicKey, (ECPrivateKey*)privateKey, publicData) != CKR_OK)
	{
		ecdh->recyclePrivateKey(privateKey);
		ecdh->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);
		return CKR_GENERAL_ERROR;
	}

	// Derive the secret
	SymmetricKey* secret = NULL;
	CK_RV rv = CKR_OK;
	if (!ecdh->deriveKey(&secret, publicKey, privateKey))
		rv = CKR_GENERAL_ERROR;
	ecdh->recyclePrivateKey(privateKey);
	ecdh->recyclePublicKey(publicKey);

	// Create the secret object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - secretAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
		default:
			secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_DERIVE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,false);

			// Common Secret Key Attributes
			if (baseKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false))
			{
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,false);
			}
			if (baseKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, true))
			{
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,bNeverExtractable);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,false);
			}

			// Secret Attributes
			ByteString secretValue = secret->getKeyBits();
			ByteString value;
			ByteString plainKCV;
			ByteString kcv;

			// For generic and AES keys:
			// default to return max size available.
			if (byteLen == 0)
			{
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						byteLen = secretValue.size();
						break;
					case CKK_AES:
						if (secretValue.size() >= 32)
							byteLen = 32;
						else if (secretValue.size() >= 24)
							byteLen = 24;
						else
							byteLen = 16;
				}
			}

			if (byteLen > secretValue.size())
			{
				INFO_MSG("The derived secret is too short");
				bOK = false;
			}
			else
			{
				// Truncate value when requested, remove from the leading end
				if (byteLen < secretValue.size())
					secretValue.split(secretValue.size() - byteLen);

				// Fix the odd parity for DES
				if (keyType == CKK_DES ||
				    keyType == CKK_DES2 ||
				    keyType == CKK_DES3)
				{
					for (size_t i = 0; i < secretValue.size(); i++)
					{
						secretValue[i] = odd_parity[secretValue[i]];
					}
				}

				// Get the KCV
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						secret->setBitLen(byteLen * 8);
						plainKCV = secret->getKeyCheckValue();
						break;
					case CKK_AES:
						secret->setBitLen(byteLen * 8);
						plainKCV = ((AESKey*)secret)->getKeyCheckValue();
						break;
					default:
						bOK = false;
						break;
				}

				if (isPrivate)
				{
					token->encrypt(secretValue, value);
					token->encrypt(plainKCV, kcv);
				}
				else
				{
					value = secretValue;
					kcv = plainKCV;
				}
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	ecdh->recycleSymmetricKey(secret);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecdh);

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* ossecret = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (ossecret) ossecret->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}


// Generate a DSA key pair
#ifdef WITH_EDDSA
CK_RV SoftHSM::deriveEDDSA
(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_KEY_TYPE keyType,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;

	if ((pMechanism->pParameter == NULL_PTR) ||
	    (pMechanism->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS)))
	{
		DEBUG_MSG("pParameter must be of type CK_ECDH1_DERIVE_PARAMS");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->kdf != CKD_NULL)
	{
		DEBUG_MSG("kdf must be CKD_NULL");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if ((CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulSharedDataLen != 0) ||
	    (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pSharedData != NULL_PTR))
	{
		DEBUG_MSG("there must be no shared data");
		return CKR_MECHANISM_PARAM_INVALID;
	}
	if ((CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen == 0) ||
	    (CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pPublicData == NULL_PTR))
	{
		DEBUG_MSG("there must be a public data");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired parameter information
	size_t byteLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE:
				INFO_MSG("CKA_VALUE must not be included");
				return CKR_ATTRIBUTE_READ_ONLY;
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				byteLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// Check the length
	// byteLen == 0 impiles return max size the ECC can derive
	switch (keyType)
	{
		case CKK_GENERIC_SECRET:
			break;
		case CKK_AES:
			if (byteLen != 0 && byteLen != 16 && byteLen != 24 && byteLen != 32)
			{
				INFO_MSG("CKA_VALUE_LEN must be 0, 16, 24, or 32");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	// Get the base key handle
	OSObject *baseKey = (OSObject *)handleManager->getObject(hBaseKey);
	if (baseKey == NULL || !baseKey->isValid())
		return CKR_KEY_HANDLE_INVALID;

	// Get the EDDSA algorithm handler
	AsymmetricAlgorithm* eddsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
	if (eddsa == NULL)
		return CKR_MECHANISM_INVALID;

	// Get the keys
	PrivateKey* privateKey = eddsa->newPrivateKey();
	if (privateKey == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
		return CKR_HOST_MEMORY;
	}
	if (getEDPrivateKey((EDPrivateKey*)privateKey, token, baseKey) != CKR_OK)
	{
		eddsa->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
		return CKR_GENERAL_ERROR;
	}

	ByteString publicData;
	publicData.resize(CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen);
	memcpy(&publicData[0],
	       CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->pPublicData,
	       CK_ECDH1_DERIVE_PARAMS_PTR(pMechanism->pParameter)->ulPublicDataLen);
	PublicKey* publicKey = eddsa->newPublicKey();
	if (publicKey == NULL)
	{
		eddsa->recyclePrivateKey(privateKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
		return CKR_HOST_MEMORY;
	}
	if (getEDDHPublicKey((EDPublicKey*)publicKey, (EDPrivateKey*)privateKey, publicData) != CKR_OK)
	{
		eddsa->recyclePrivateKey(privateKey);
		eddsa->recyclePublicKey(publicKey);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);
		return CKR_GENERAL_ERROR;
	}

	// Derive the secret
	SymmetricKey* secret = NULL;
	CK_RV rv = CKR_OK;
	if (!eddsa->deriveKey(&secret, publicKey, privateKey))
		rv = CKR_GENERAL_ERROR;
	eddsa->recyclePrivateKey(privateKey);
	eddsa->recyclePublicKey(publicKey);

	// Create the secret object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	if (ulCount > (maxAttribs - secretAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
		default:
			secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_DERIVE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,false);

			// Common Secret Key Attributes
			if (baseKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false))
			{
				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,bAlwaysSensitive);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE,false);
			}
			if (baseKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, true))
			{
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,bNeverExtractable);
			}
			else
			{
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE,false);
			}

			// Secret Attributes
			ByteString secretValue = secret->getKeyBits();
			ByteString value;
			ByteString plainKCV;
			ByteString kcv;

			// For generic and AES keys:
			// default to return max size available.
			if (byteLen == 0)
			{
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						byteLen = secretValue.size();
						break;
					case CKK_AES:
						if (secretValue.size() >= 32)
							byteLen = 32;
						else if (secretValue.size() >= 24)
							byteLen = 24;
						else
							byteLen = 16;
				}
			}

			if (byteLen > secretValue.size())
			{
				INFO_MSG("The derived secret is too short");
				bOK = false;
			}
			else
			{
				// Truncate value when requested, remove from the leading end
				if (byteLen < secretValue.size())
					secretValue.split(secretValue.size() - byteLen);

				// Get the KCV
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						secret->setBitLen(byteLen * 8);
						plainKCV = secret->getKeyCheckValue();
						break;
					case CKK_AES:
						secret->setBitLen(byteLen * 8);
						plainKCV = ((AESKey*)secret)->getKeyCheckValue();
						break;
					default:
						bOK = false;
						break;
				}

				if (isPrivate)
				{
					token->encrypt(secretValue, value);
					token->encrypt(plainKCV, kcv);
				}
				else
				{
					value = secretValue;
					kcv = plainKCV;
				}
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Clean up
	eddsa->recycleSymmetricKey(secret);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(eddsa);

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* ossecret = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (ossecret) ossecret->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}
#endif

// Derive an symmetric secret
CK_RV SoftHSM::deriveSymmetric
(CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hBaseKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_KEY_TYPE keyType,
	CK_BBOOL isOnToken,
	CK_BBOOL isPrivate)
{
	*phKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE_PTR phOtherKey = CK_INVALID_HANDLE;
	OSObject *otherKey = NULL_PTR;

	if (pMechanism->pParameter == NULL_PTR)
	{
		DEBUG_MSG("pParameter must be supplied");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	ByteString data;

	if (pMechanism->mechanism == CKM_AES_ECB_ENCRYPT_DATA &&
		 pMechanism->ulParameterLen == sizeof(CK_KEY_DERIVATION_STRING_DATA))
	{
		CK_BYTE_PTR pData = CK_KEY_DERIVATION_STRING_DATA_PTR(pMechanism->pParameter)->pData;
		CK_ULONG ulLen = CK_KEY_DERIVATION_STRING_DATA_PTR(pMechanism->pParameter)->ulLen;
		if (ulLen == 0 || pData == NULL_PTR)
		{
			DEBUG_MSG("There must be data in the parameter");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (ulLen % 16 != 0)
		{
			DEBUG_MSG("The data must be a multiple of 16 bytes long");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		data.resize(ulLen);
		memcpy(&data[0],
		       pData,
		       ulLen);
	}
	else if ((pMechanism->mechanism == CKM_AES_CBC_ENCRYPT_DATA) &&
		 pMechanism->ulParameterLen == sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS))
	{
		CK_BYTE_PTR pData = CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR(pMechanism->pParameter)->pData;
		CK_ULONG length = CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR(pMechanism->pParameter)->length;
		if (length == 0 || pData == NULL_PTR)
		{
			DEBUG_MSG("There must be data in the parameter");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (length % 16 != 0)
		{
			DEBUG_MSG("The data must be a multiple of 16 bytes long");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		data.resize(length);
		memcpy(&data[0],
		       pData,
		       length);
	}
	else if ((pMechanism->mechanism == CKM_CONCATENATE_DATA_AND_BASE ||
			pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_DATA) &&
		 pMechanism->ulParameterLen == sizeof(CK_KEY_DERIVATION_STRING_DATA))
	{
		CK_BYTE_PTR pData = CK_KEY_DERIVATION_STRING_DATA_PTR(pMechanism->pParameter)->pData;
		CK_ULONG length = CK_KEY_DERIVATION_STRING_DATA_PTR(pMechanism->pParameter)->ulLen;
		if (length == 0 || pData == NULL_PTR)
		{
			DEBUG_MSG("There must be data in the parameter");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		data.resize(length);
		memcpy(&data[0],
		       pData,
               length);
	}
	else if (pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_KEY &&
		 pMechanism->ulParameterLen == sizeof(CK_OBJECT_HANDLE))
	{
		phOtherKey = CK_OBJECT_HANDLE_PTR(pMechanism->pParameter);
		if (phOtherKey == CK_INVALID_HANDLE)
		{
			DEBUG_MSG("There must be handle in the parameter");
			return CKR_MECHANISM_PARAM_INVALID;
		}
		DEBUG_MSG("(0x%08X) Other key handle is (0x%08X)", phOtherKey, *phOtherKey);
	}
	else
	{
		DEBUG_MSG("pParameter is invalid");
		return CKR_MECHANISM_PARAM_INVALID;
	}

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract another key
	if (pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_KEY) {
		// Check the key handle.
		otherKey = (OSObject *)handleManager->getObject(*phOtherKey);
		if (otherKey == NULL_PTR || !otherKey->isValid()) return CKR_OBJECT_HANDLE_INVALID;
		if (otherKey->getBooleanValue(CKA_PRIVATE, true)) {
			bool bOK = token->decrypt(otherKey->getByteStringValue(CKA_VALUE), data);
			if (!bOK) return CKR_GENERAL_ERROR;
		} else {
			data = otherKey->getByteStringValue(CKA_VALUE);
		}
	}

	// Extract desired parameter information
	size_t byteLen = 0;
	bool checkValue = true;
	for (CK_ULONG i = 0; i < ulCount; i++)
	{
		switch (pTemplate[i].type)
		{
			case CKA_VALUE:
				INFO_MSG("CKA_VALUE must not be included");
				return CKR_ATTRIBUTE_READ_ONLY;
			case CKA_VALUE_LEN:
				if (pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					INFO_MSG("CKA_VALUE_LEN does not have the size of CK_ULONG");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				byteLen = *(CK_ULONG*)pTemplate[i].pValue;
				break;
			case CKA_CHECK_VALUE:
				if (pTemplate[i].ulValueLen > 0)
				{
					INFO_MSG("CKA_CHECK_VALUE must be a no-value (0 length) entry");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				checkValue = false;
				break;
			default:
				break;
		}
	}

	// Check the length if it specified or a mechanism is not one of misc mechanisms
	if (byteLen > 0 || (pMechanism->mechanism != CKM_CONCATENATE_DATA_AND_BASE &&
			pMechanism->mechanism != CKM_CONCATENATE_BASE_AND_DATA &&
			pMechanism->mechanism != CKM_CONCATENATE_BASE_AND_KEY)) {
		switch (keyType) {
			case CKK_GENERIC_SECRET:
				if (byteLen == 0) {
					INFO_MSG("CKA_VALUE_LEN must be set");
					return CKR_TEMPLATE_INCOMPLETE;
				}
				break;
			case CKK_AES:
				if (byteLen != 16 && byteLen != 24 && byteLen != 32) {
					INFO_MSG("CKA_VALUE_LEN must be 16, 24, or 32");
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				break;
			default:
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	// Get the symmetric algorithm matching the mechanism
	SymAlgo::Type algo = SymAlgo::Unknown;
	SymMode::Type mode = SymMode::Unknown;
	bool padding = false;
	ByteString iv;
	size_t bb = 8;
	switch(pMechanism->mechanism) {
		case CKM_AES_ECB_ENCRYPT_DATA:
			algo = SymAlgo::AES;
			mode = SymMode::ECB;
			break;
		case CKM_AES_CBC_ENCRYPT_DATA:
			algo = SymAlgo::AES;
			mode = SymMode::CBC;
			iv.resize(16);
			memcpy(&iv[0],
			       &(CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR(pMechanism->pParameter)->iv[0]),
			       16);
			break;
	    case CKM_CONCATENATE_DATA_AND_BASE:
	    case CKM_CONCATENATE_BASE_AND_DATA:
	    case CKM_CONCATENATE_BASE_AND_KEY:
	        break;
		default:
			return CKR_MECHANISM_INVALID;
	}

	// Check the key handle
	OSObject *baseKey = (OSObject *)handleManager->getObject(hBaseKey);
	if (baseKey == NULL_PTR || !baseKey->isValid()) return CKR_OBJECT_HANDLE_INVALID;

    // Get the data
    ByteString secretValue;

    if (pMechanism->mechanism == CKM_CONCATENATE_DATA_AND_BASE ||
			pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_DATA ||
			pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_KEY) {
        // Get the key data
        ByteString keydata;

        // Get the CKA_PRIVATE attribute, when the attribute is not present use default false
        bool isKeyPrivate = baseKey->getBooleanValue(CKA_PRIVATE, false);
        if (isKeyPrivate)
        {
            bool bOK = token->decrypt(baseKey->getByteStringValue(CKA_VALUE), keydata);
            if (!bOK) return CKR_GENERAL_ERROR;
        }
        else
        {
            keydata = baseKey->getByteStringValue(CKA_VALUE);
        }

        if (pMechanism->mechanism == CKM_CONCATENATE_DATA_AND_BASE) {
			secretValue += data;
			secretValue += keydata;
		} else if (pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_DATA ||
				pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_KEY) {
			secretValue += keydata;
			secretValue += data;
        } else {
        	return CKR_MECHANISM_INVALID;
        }

        // If the CKA_VALUE_LEN attribute is not present use computed size
        if (byteLen == 0) {
            byteLen = data.size() + keydata.size();
            CK_RV rv = checkKeyLength(keyType, byteLen);
            if (rv != CKR_OK) {
            	return rv;
            }
        }
	} else {
        SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
        if (cipher == NULL) return CKR_MECHANISM_INVALID;

        SymmetricKey* secretkey = new SymmetricKey();

        if (getSymmetricKey(secretkey, token, baseKey) != CKR_OK)
        {
            cipher->recycleKey(secretkey);
            CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
            return CKR_GENERAL_ERROR;
        }

        // adjust key bit length
        secretkey->setBitLen(secretkey->getKeyBits().size() * bb);

        // Initialize encryption
        if (!cipher->encryptInit(secretkey, mode, iv, padding)) {
            cipher->recycleKey(secretkey);
            CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
            return CKR_MECHANISM_INVALID;
        }

        // Encrypt the data
        if (!cipher->encryptUpdate(data, secretValue)) {
            cipher->recycleKey(secretkey);
            CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
            return CKR_GENERAL_ERROR;
        }

        // Finalize encryption
        ByteString encryptedFinal;
        if (!cipher->encryptFinal(encryptedFinal)) {
            cipher->recycleKey(secretkey);
            CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
            return CKR_GENERAL_ERROR;
        }
        cipher->recycleKey(secretkey);
        CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
        secretValue += encryptedFinal;
    }

	// Create the secret object using C_CreateObject
	const CK_ULONG maxAttribs = 32;
	CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE secretAttribs[maxAttribs] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_TOKEN, &isOnToken, sizeof(isOnToken) },
		{ CKA_PRIVATE, &isPrivate, sizeof(isPrivate) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
	};
	CK_ULONG secretAttribsCount = 4;

	// Add the additional
	CK_RV rv = CKR_OK;
	if (ulCount > (maxAttribs - secretAttribsCount))
		rv = CKR_TEMPLATE_INCONSISTENT;
	for (CK_ULONG i=0; i < ulCount && rv == CKR_OK; ++i)
	{
		switch (pTemplate[i].type)
		{
			case CKA_CLASS:
			case CKA_TOKEN:
			case CKA_PRIVATE:
			case CKA_KEY_TYPE:
			case CKA_CHECK_VALUE:
				continue;
			default:
				secretAttribs[secretAttribsCount++] = pTemplate[i];
		}
	}

	if (rv == CKR_OK)
		rv = this->CreateObject(hSession, secretAttribs, secretAttribsCount, phKey, OBJECT_OP_DERIVE);

	// Store the attributes that are being supplied
	if (rv == CKR_OK)
	{
		OSObject* osobject = (OSObject*)handleManager->getObject(*phKey);
		if (osobject == NULL_PTR || !osobject->isValid()) {
			rv = CKR_FUNCTION_FAILED;
		} else if (osobject->startTransaction()) {
			bool bOK = true;

			// Common Attributes
			bOK = bOK && osobject->setAttribute(CKA_LOCAL,false);

			// Common Secret Key Attributes
			if (pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_KEY) {
				// [PKCS#11 v2.40, 2.31.3]
				// If either of the two original keys has its CKA_SENSITIVE attribute
				// set to CK_TRUE, so does the derived key.  If not, then the derived
				// key’s CKA_SENSITIVE attribute is set either from the supplied template
				// or from a default value.
				bool bSensitive = baseKey->getBooleanValue(CKA_SENSITIVE, true) ||
								  otherKey->getBooleanValue(CKA_SENSITIVE, true);
				if (bSensitive) {
					bOK = bOK && osobject->setAttribute(CKA_SENSITIVE, true);
				}
				// If either of the two original keys has its CKA_EXTRACTABLE attribute
				// set to CK_FALSE, so does the derived key.  If not, then the derived
				// key’s CKA_EXTRACTABLE attribute is set either from the supplied template
				// or from a default value.
				bool bExtractable = baseKey->getBooleanValue(CKA_EXTRACTABLE, true) &&
									otherKey->getBooleanValue(CKA_EXTRACTABLE, true);
				if (!bExtractable) {
					bOK = bOK && osobject->setAttribute(CKA_EXTRACTABLE, false);
				}
				// The derived key’s CKA_ALWAYS_SENSITIVE attribute is set to CK_TRUE
				// if and only if both of the original keys have their CKA_ALWAYS_SENSITIVE
				// attributes set to CK_TRUE.
				bool bAlwaysSensitive = baseKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false) &&
										otherKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, bAlwaysSensitive);
				// The derived key’s CKA_NEVER_EXTRACTABLE attribute is set to CK_TRUE
				// if and only if both of the original keys have their CKA_NEVER_EXTRACTABLE
				// attributes set to CK_TRUE
				bool bNeverExtractable = baseKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, false) &&
										 otherKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, bNeverExtractable);
			}
			else if (pMechanism->mechanism == CKM_CONCATENATE_BASE_AND_DATA ||
				 pMechanism->mechanism == CKM_CONCATENATE_DATA_AND_BASE)
			{
				// [PKCS#11 v2.40, 2.31.4-2.31.7]
				// If the base key has its CKA_SENSITIVE attribute set to CK_TRUE, so does the derived key.
				// If not, then the derived key’s CKA_SENSITIVE attribute is set either from the supplied
				// template or from a default value.
				if (baseKey->getBooleanValue(CKA_SENSITIVE, true)) {
					bOK = bOK && osobject->setAttribute(CKA_SENSITIVE, true);
				}
				// If the base key has its CKA_EXTRACTABLE attribute set to CK_FALSE, so does the derived key.
				// If not, then the derived key’s CKA_EXTRACTABLE attribute is set either from the supplied
				// template or from a default value.
				if (!baseKey->getBooleanValue(CKA_EXTRACTABLE, false)) {
					bOK = bOK && osobject->setAttribute(CKA_EXTRACTABLE, false);
				}
				// The derived key’s CKA_ALWAYS_SENSITIVE attribute is set to CK_TRUE if and only
				// if the base key has its CKA_ALWAYS_SENSITIVE attribute set to CK_TRUE.
				bool bAlwaysSensitive = baseKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, bAlwaysSensitive);
				// The derived key’s CKA_NEVER_EXTRACTABLE attribute is set to CK_TRUE if and only
				// if the base key has its CKA_NEVER_EXTRACTABLE attribute set to CK_TRUE.
				bool bNeverExtractable = baseKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, false);
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);
			} else {
				if (baseKey->getBooleanValue(CKA_ALWAYS_SENSITIVE, false)) {
					bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
					bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, bAlwaysSensitive);
				} else {
					bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, false);
				}
				if (baseKey->getBooleanValue(CKA_NEVER_EXTRACTABLE, true)) {
					bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
					bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);
				} else {
					bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, false);
				}
			}

			ByteString value;
			ByteString plainKCV;
			ByteString kcv;

			if (byteLen > secretValue.size())
			{
				INFO_MSG("The derived secret is too short");
				bOK = false;
			}
			else
			{
				// Truncate value when requested, remove from the trailing end
				if (byteLen < secretValue.size())
					secretValue.resize(byteLen);

				// Get the KCV
				SymmetricKey* secret = new SymmetricKey();
				secret->setKeyBits(secretValue);
				switch (keyType)
				{
					case CKK_GENERIC_SECRET:
						secret->setBitLen(byteLen * 8);
						plainKCV = secret->getKeyCheckValue();
						break;
					case CKK_AES:
						secret->setBitLen(byteLen * 8);
						plainKCV = ((AESKey*)secret)->getKeyCheckValue();
						break;
					default:
						bOK = false;
						break;
				}
				delete secret;

				if (isPrivate)
				{
					token->encrypt(secretValue, value);
					token->encrypt(plainKCV, kcv);
				}
				else
				{
					value = secretValue;
					kcv = plainKCV;
				}
			}
			bOK = bOK && osobject->setAttribute(CKA_VALUE, value);
			if (checkValue)
				bOK = bOK && osobject->setAttribute(CKA_CHECK_VALUE, kcv);

			if (bOK)
				bOK = osobject->commitTransaction();
			else
				osobject->abortTransaction();

			if (!bOK)
				rv = CKR_FUNCTION_FAILED;
		} else
			rv = CKR_FUNCTION_FAILED;
	}

	// Remove secret that may have been created already when the function fails.
	if (rv != CKR_OK)
	{
		if (*phKey != CK_INVALID_HANDLE)
		{
			OSObject* ossecret = (OSObject*)handleManager->getObject(*phKey);
			handleManager->destroyObject(*phKey);
			if (ossecret) ossecret->destroyObject();
			*phKey = CK_INVALID_HANDLE;
		}
	}

	return rv;
}


CK_RV SoftHSM::getRSAPrivateKey(RSAPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// RSA Private Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	ByteString privateExponent;
	ByteString prime1;
	ByteString prime2;
	ByteString exponent1;
	ByteString exponent2;
	ByteString coefficient;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_MODULUS), modulus);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PUBLIC_EXPONENT), publicExponent);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PRIVATE_EXPONENT), privateExponent);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PRIME_1), prime1);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PRIME_2), prime2);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EXPONENT_1), exponent1);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EXPONENT_2), exponent2);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_COEFFICIENT), coefficient);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		modulus = key->getByteStringValue(CKA_MODULUS);
		publicExponent = key->getByteStringValue(CKA_PUBLIC_EXPONENT);
		privateExponent = key->getByteStringValue(CKA_PRIVATE_EXPONENT);
		prime1 = key->getByteStringValue(CKA_PRIME_1);
		prime2 = key->getByteStringValue(CKA_PRIME_2);
		exponent1 =  key->getByteStringValue(CKA_EXPONENT_1);
		exponent2 = key->getByteStringValue(CKA_EXPONENT_2);
		coefficient = key->getByteStringValue(CKA_COEFFICIENT);
	}

	privateKey->setN(modulus);
	privateKey->setE(publicExponent);
	privateKey->setD(privateExponent);
	privateKey->setP(prime1);
	privateKey->setQ(prime2);
	privateKey->setDP1(exponent1);
	privateKey->setDQ1(exponent2);
	privateKey->setPQ(coefficient);

	return CKR_OK;
}

CK_RV SoftHSM::getRSAPublicKey(RSAPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// RSA Public Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_MODULUS), modulus);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_PUBLIC_EXPONENT), publicExponent);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		modulus = key->getByteStringValue(CKA_MODULUS);
		publicExponent = key->getByteStringValue(CKA_PUBLIC_EXPONENT);
	}

	publicKey->setN(modulus);
	publicKey->setE(publicExponent);

	return CKR_OK;
}

CK_RV SoftHSM::getECPrivateKey(ECPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// EC Private Key Attributes
	ByteString group;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key->getByteStringValue(CKA_EC_PARAMS);
		value = key->getByteStringValue(CKA_VALUE);
	}

	privateKey->setEC(group);
	privateKey->setD(value);

	return CKR_OK;
}

CK_RV SoftHSM::getECPublicKey(ECPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// EC Public Key Attributes
	ByteString group;
	ByteString point;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_POINT), point);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key->getByteStringValue(CKA_EC_PARAMS);
		point = key->getByteStringValue(CKA_EC_POINT);
	}

	publicKey->setEC(group);
	publicKey->setQ(point);

	return CKR_OK;
}

CK_RV SoftHSM::getEDPrivateKey(EDPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// EDDSA Private Key Attributes
	ByteString group;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key->getByteStringValue(CKA_EC_PARAMS);
		value = key->getByteStringValue(CKA_VALUE);
	}

	privateKey->setEC(group);
	privateKey->setK(value);

	return CKR_OK;
}

CK_RV SoftHSM::getEDPublicKey(EDPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// EC Public Key Attributes
	ByteString group;
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_PARAMS), group);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_EC_POINT), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		group = key->getByteStringValue(CKA_EC_PARAMS);
		value = key->getByteStringValue(CKA_EC_POINT);
	}

	publicKey->setEC(group);
	publicKey->setA(value);

	return CKR_OK;
}



CK_RV SoftHSM::getMLDSAPrivateKey(MLDSAPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// ML-DSA Private Key Attributes: CKA_PARAMETER_SET + CKA_VALUE (PKCS#8 DER)
	CK_ULONG parameterSet = key->getUnsignedLongValue(CKA_PARAMETER_SET, CKK_VENDOR_DEFINED);
	ByteString value;
	if (isKeyPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), value))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
	}

	privateKey->setParameterSet(parameterSet);
	privateKey->setValue(value);

	return CKR_OK;
}

CK_RV SoftHSM::getMLDSAPublicKey(MLDSAPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// ML-DSA Public Key Attributes: CKA_PARAMETER_SET + CKA_VALUE (raw pub key bytes)
	CK_ULONG parameterSet = key->getUnsignedLongValue(CKA_PARAMETER_SET, CKK_VENDOR_DEFINED);
	ByteString value;
	if (isKeyPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), value))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
	}

	publicKey->setParameterSet(parameterSet);
	publicKey->setValue(value);

	return CKR_OK;
}

CK_RV SoftHSM::getSLHDSAPrivateKey(SLHDSAPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// SLH-DSA Private Key Attributes: CKA_PARAMETER_SET + CKA_VALUE (PKCS#8 DER)
	CK_ULONG parameterSet = key->getUnsignedLongValue(CKA_PARAMETER_SET, CKK_VENDOR_DEFINED);
	ByteString value;
	if (isKeyPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), value))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
	}

	privateKey->setParameterSet(parameterSet);
	privateKey->setValue(value);

	return CKR_OK;
}

CK_RV SoftHSM::getSLHDSAPublicKey(SLHDSAPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// SLH-DSA Public Key Attributes: CKA_PARAMETER_SET + CKA_VALUE (raw pub key bytes)
	CK_ULONG parameterSet = key->getUnsignedLongValue(CKA_PARAMETER_SET, CKK_VENDOR_DEFINED);
	ByteString value;
	if (isKeyPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), value))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
	}

	publicKey->setParameterSet(parameterSet);
	publicKey->setValue(value);

	return CKR_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// ML-KEM (FIPS 203, PKCS#11 v3.2) — key helpers
// ─────────────────────────────────────────────────────────────────────────────


CK_RV SoftHSM::generateMLKEM
(CK_SESSION_HANDLE hSession,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey,
	CK_BBOOL isPublicKeyOnToken,
	CK_BBOOL isPublicKeyPrivate,
	CK_BBOOL isPrivateKeyOnToken,
	CK_BBOOL isPrivateKeyPrivate)
{
	*phPublicKey = CK_INVALID_HANDLE;
	*phPrivateKey = CK_INVALID_HANDLE;

	// Get the session
	auto sessionGuard = handleManager->getSessionShared(hSession);
	Session* session = sessionGuard.get();
	if (session == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Get the token
	Token* token = session->getToken();
	if (token == NULL)
		return CKR_GENERAL_ERROR;

	// Extract desired key information: CKA_PARAMETER_SET selects the ML-KEM variant
	CK_ULONG parameterSet = CKP_ML_KEM_768;  // default
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		if (pPublicKeyTemplate[i].type == CKA_PARAMETER_SET && pPublicKeyTemplate[i].ulValueLen == sizeof(CK_ULONG))
		{
			parameterSet = *(CK_ULONG*)pPublicKeyTemplate[i].pValue;
			break;
		}
	}

	// Set the parameters
	MLKEMParameters p;
	p.setParameterSet(parameterSet);

	// Generate key pair
	AsymmetricKeyPair* kp = NULL;
	AsymmetricAlgorithm* mlkem = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLKEM);
	if (mlkem == NULL) return CKR_GENERAL_ERROR;
	if (!mlkem->generateKeyPair(&kp, &p))
	{
		ERROR_MSG("Could not generate ML-KEM key pair");
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return CKR_GENERAL_ERROR;
	}

	MLKEMPublicKey* pub = (MLKEMPublicKey*) kp->getPublicKey();
	MLKEMPrivateKey* priv = (MLKEMPrivateKey*) kp->getPrivateKey();

	CK_RV rv = CKR_OK;

	// Create a public key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE publicKeyType = CKK_ML_KEM;
		CK_ATTRIBUTE publicKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &isPublicKeyOnToken, sizeof(isPublicKeyOnToken) },
			{ CKA_PRIVATE, &isPublicKeyPrivate, sizeof(isPublicKeyPrivate) },
			{ CKA_KEY_TYPE, &publicKeyType, sizeof(publicKeyType) },
		};
		CK_ULONG publicKeyAttribsCount = 4;

		if (ulPublicKeyAttributeCount > (maxAttribs - publicKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPublicKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
					continue;
				default:
					publicKeyAttribs[publicKeyAttribsCount++] = pPublicKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession, publicKeyAttribs, publicKeyAttribsCount, phPublicKey, OBJECT_OP_GENERATE);

		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPublicKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				bOK = bOK && osobject->setAttribute(CKA_LOCAL, true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_ML_KEM_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM, ulKeyGenMechanism);

				// ML-KEM Public Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_PARAMETER_SET, (unsigned long)pub->getParameterSet());
				ByteString pubValue;
				if (isPublicKeyPrivate)
					token->encrypt(pub->getValue(), pubValue);
				else
					pubValue = pub->getValue();
				bOK = bOK && osobject->setAttribute(CKA_VALUE, pubValue);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	// Create a private key using C_CreateObject
	if (rv == CKR_OK)
	{
		const CK_ULONG maxAttribs = 32;
		CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE privateKeyType = CKK_ML_KEM;
		CK_ATTRIBUTE privateKeyAttribs[maxAttribs] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &isPrivateKeyOnToken, sizeof(isPrivateKeyOnToken) },
			{ CKA_PRIVATE, &isPrivateKeyPrivate, sizeof(isPrivateKeyPrivate) },
			{ CKA_KEY_TYPE, &privateKeyType, sizeof(privateKeyType) },
		};
		CK_ULONG privateKeyAttribsCount = 4;
		if (ulPrivateKeyAttributeCount > (maxAttribs - privateKeyAttribsCount))
			rv = CKR_TEMPLATE_INCONSISTENT;
		for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount && rv == CKR_OK; ++i)
		{
			switch (pPrivateKeyTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_KEY_TYPE:
				case CKA_PARAMETER_SET: // ck4: set directly after CreateObject
					continue;
				default:
					privateKeyAttribs[privateKeyAttribsCount++] = pPrivateKeyTemplate[i];
			}
		}

		if (rv == CKR_OK)
			rv = this->CreateObject(hSession, privateKeyAttribs, privateKeyAttribsCount, phPrivateKey, OBJECT_OP_GENERATE);

		if (rv == CKR_OK)
		{
			OSObject* osobject = (OSObject*)handleManager->getObject(*phPrivateKey);
			if (osobject == NULL_PTR || !osobject->isValid()) {
				rv = CKR_FUNCTION_FAILED;
			} else if (osobject->startTransaction()) {
				bool bOK = true;

				bOK = bOK && osobject->setAttribute(CKA_LOCAL, true);
				CK_ULONG ulKeyGenMechanism = (CK_ULONG)CKM_ML_KEM_KEY_PAIR_GEN;
				bOK = bOK && osobject->setAttribute(CKA_KEY_GEN_MECHANISM, ulKeyGenMechanism);

				bool bAlwaysSensitive = osobject->getBooleanValue(CKA_SENSITIVE, false);
				bOK = bOK && osobject->setAttribute(CKA_ALWAYS_SENSITIVE, bAlwaysSensitive);
				bool bNeverExtractable = osobject->getBooleanValue(CKA_EXTRACTABLE, false) == false;
				bOK = bOK && osobject->setAttribute(CKA_NEVER_EXTRACTABLE, bNeverExtractable);

				// ML-KEM Private Key Attributes
				bOK = bOK && osobject->setAttribute(CKA_PARAMETER_SET, (unsigned long)priv->getParameterSet());
				ByteString privValue;
				if (isPrivateKeyPrivate)
					token->encrypt(priv->getValue(), privValue);
				else
					privValue = priv->getValue();
				bOK = bOK && osobject->setAttribute(CKA_VALUE, privValue);

				if (bOK)
					bOK = osobject->commitTransaction();
				else
					osobject->abortTransaction();

				if (!bOK)
					rv = CKR_FUNCTION_FAILED;
			} else
				rv = CKR_FUNCTION_FAILED;
		}
	}

	cleanupKeyPair(mlkem, kp, NULL, phPublicKey, phPrivateKey, rv);

	return rv;
}

CK_RV SoftHSM::getECDHPublicKey(ECPublicKey* publicKey, ECPrivateKey* privateKey, ByteString& pubData)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;

	// Copy Domain Parameters from Private Key
	publicKey->setEC(privateKey->getEC());

	// Set value
	ByteString data = getECDHPubData(pubData);
	publicKey->setQ(data);

	return CKR_OK;
}

CK_RV SoftHSM::getEDDHPublicKey(EDPublicKey* publicKey, EDPrivateKey* privateKey, ByteString& pubData)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;

	// Copy Domain Parameters from Private Key
	publicKey->setEC(privateKey->getEC());

	// Set value
	ByteString data = getECDHPubData(pubData);
	publicKey->setA(data);

	return CKR_OK;
}

// ECDH pubData can be in RAW or DER format.
// Need to convert RAW as SoftHSM uses DER.
ByteString SoftHSM::getECDHPubData(ByteString& pubData)
{
	size_t len = pubData.size();
	size_t controlOctets = 2;
	if (len == 32 || len == 56 || len == 65 || len == 97 || len == 133)
	{
		// Raw: Length matches the public key size of:
		// EDDSA: X25519, X448
		// ECDSA: P-256, P-384, or P-521
		controlOctets = 0;
	}
	else if (len < controlOctets || pubData[0] != 0x04)
	{
		// Raw: Too short or does not start with 0x04
		controlOctets = 0;
	}
	else if (pubData[1] < 0x80)
	{
		// Raw: Length octet does not match remaining data length
		if (pubData[1] != (len - controlOctets)) controlOctets = 0;
	}
	else
	{
		size_t lengthOctets = pubData[1] & 0x7F;
		controlOctets += lengthOctets;

		if (controlOctets >= len)
		{
			// Raw: Too short
			controlOctets = 0;
		}
		else
		{
			ByteString length(&pubData[2], lengthOctets);

			if (length.long_val() != (len - controlOctets))
			{
				// Raw: Length octets does not match remaining data length
				controlOctets = 0;
			}
		}
	}

	// DER format
	if (controlOctets != 0) return pubData;

	return DERUTIL::raw2Octet(pubData);
}



CK_RV SoftHSM::getSymmetricKey(SymmetricKey* skey, Token* token, OSObject* key)
{
	if (skey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	ByteString keybits;
	if (isKeyPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), keybits))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		keybits = key->getByteStringValue(CKA_VALUE);
	}

	skey->setKeyBits(keybits);

	return CKR_OK;
}

bool SoftHSM::setRSAPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate) const
{
	AsymmetricAlgorithm* rsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::RSA);
	if (rsa == NULL)
		return false;
	PrivateKey* priv = rsa->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		rsa->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);
		return false;
	}
	// RSA Private Key Attributes
	ByteString modulus;
	ByteString publicExponent;
	ByteString privateExponent;
	ByteString prime1;
	ByteString prime2;
	ByteString exponent1;
	ByteString exponent2;
	ByteString coefficient;
	if (isPrivate)
	{
		token->encrypt(((RSAPrivateKey*)priv)->getN(), modulus);
		token->encrypt(((RSAPrivateKey*)priv)->getE(), publicExponent);
		token->encrypt(((RSAPrivateKey*)priv)->getD(), privateExponent);
		token->encrypt(((RSAPrivateKey*)priv)->getP(), prime1);
		token->encrypt(((RSAPrivateKey*)priv)->getQ(), prime2);
		token->encrypt(((RSAPrivateKey*)priv)->getDP1(), exponent1);
		token->encrypt(((RSAPrivateKey*)priv)->getDQ1(), exponent2);
		token->encrypt(((RSAPrivateKey*)priv)->getPQ(), coefficient);
	}
	else
	{
		modulus = ((RSAPrivateKey*)priv)->getN();
		publicExponent = ((RSAPrivateKey*)priv)->getE();
		privateExponent = ((RSAPrivateKey*)priv)->getD();
		prime1 = ((RSAPrivateKey*)priv)->getP();
		prime2 = ((RSAPrivateKey*)priv)->getQ();
		exponent1 =  ((RSAPrivateKey*)priv)->getDP1();
		exponent2 = ((RSAPrivateKey*)priv)->getDQ1();
		coefficient = ((RSAPrivateKey*)priv)->getPQ();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_MODULUS, modulus);
	bOK = bOK && key->setAttribute(CKA_PUBLIC_EXPONENT, publicExponent);
	bOK = bOK && key->setAttribute(CKA_PRIVATE_EXPONENT, privateExponent);
	bOK = bOK && key->setAttribute(CKA_PRIME_1, prime1);
	bOK = bOK && key->setAttribute(CKA_PRIME_2, prime2);
	bOK = bOK && key->setAttribute(CKA_EXPONENT_1,exponent1);
	bOK = bOK && key->setAttribute(CKA_EXPONENT_2, exponent2);
	bOK = bOK && key->setAttribute(CKA_COEFFICIENT, coefficient);

	rsa->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(rsa);

	return bOK;
}



bool SoftHSM::setECPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate) const
{
	AsymmetricAlgorithm* ecc = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::ECDSA);
	if (ecc == NULL)
		return false;
	PrivateKey* priv = ecc->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		ecc->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);
		return false;
	}
	// EC Private Key Attributes
	ByteString group;
	ByteString value;
	if (isPrivate)
	{
		token->encrypt(((ECPrivateKey*)priv)->getEC(), group);
		token->encrypt(((ECPrivateKey*)priv)->getD(), value);
	}
	else
	{
		group = ((ECPrivateKey*)priv)->getEC();
		value = ((ECPrivateKey*)priv)->getD();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_EC_PARAMS, group);
	bOK = bOK && key->setAttribute(CKA_VALUE, value);

	ecc->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);

	return bOK;
}

bool SoftHSM::setEDPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate) const
{
	AsymmetricAlgorithm* ecc = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::EDDSA);
	if (ecc == NULL)
		return false;
	PrivateKey* priv = ecc->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		ecc->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);
		return false;
	}
	// EC Private Key Attributes
	ByteString group;
	ByteString value;
	if (isPrivate)
	{
		token->encrypt(((EDPrivateKey*)priv)->getEC(), group);
		token->encrypt(((EDPrivateKey*)priv)->getK(), value);
	}
	else
	{
		group = ((EDPrivateKey*)priv)->getEC();
		value = ((EDPrivateKey*)priv)->getK();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_EC_PARAMS, group);
	bOK = bOK && key->setAttribute(CKA_VALUE, value);

	ecc->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(ecc);

	return bOK;
}


CK_RV SoftHSM::MechParamCheckRSAPKCSOAEP(CK_MECHANISM_PTR pMechanism)
{
	// This is a programming error
	if (pMechanism->mechanism != CKM_RSA_PKCS_OAEP) {
		ERROR_MSG("MechParamCheckRSAPKCSOAEP called on wrong mechanism");
		return CKR_GENERAL_ERROR;
	}

	if (pMechanism->pParameter == NULL_PTR ||
	    pMechanism->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS))
	{
		ERROR_MSG("pParameter must be of type CK_RSA_PKCS_OAEP_PARAMS");
		return CKR_ARGUMENTS_BAD;
	}

	CK_RSA_PKCS_OAEP_PARAMS_PTR params = (CK_RSA_PKCS_OAEP_PARAMS_PTR)pMechanism->pParameter;

	// Validate hash algorithm and matching MGF
	bool validCombo = false;
	if (params->hashAlg == CKM_SHA_1    && params->mgf == CKG_MGF1_SHA1)    validCombo = true;
	if (params->hashAlg == CKM_SHA224   && params->mgf == CKG_MGF1_SHA224)  validCombo = true;
	if (params->hashAlg == CKM_SHA256   && params->mgf == CKG_MGF1_SHA256)  validCombo = true;
	if (params->hashAlg == CKM_SHA384   && params->mgf == CKG_MGF1_SHA384)  validCombo = true;
	if (params->hashAlg == CKM_SHA512   && params->mgf == CKG_MGF1_SHA512)  validCombo = true;
	if (!validCombo)
	{
		ERROR_MSG("Invalid hashAlg/mgf combination for RSA-OAEP");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->source != CKZ_DATA_SPECIFIED)
	{
		ERROR_MSG("source must be CKZ_DATA_SPECIFIED");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->pSourceData != NULL)
	{
		ERROR_MSG("pSourceData must be NULL");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->ulSourceDataLen != 0)
	{
		ERROR_MSG("ulSourceDataLen must be 0");
		return CKR_ARGUMENTS_BAD;
	}
	return CKR_OK;
}


CK_RV SoftHSM::MechParamCheckRSAAESKEYWRAP(CK_MECHANISM_PTR pMechanism)
{
	// This is a programming error
	if (pMechanism->mechanism != CKM_RSA_AES_KEY_WRAP) {
		ERROR_MSG("MechParamCheckRSAAESKEYWRAP called on wrong mechanism");
		return CKR_GENERAL_ERROR;
	}
	if (pMechanism->pParameter == NULL_PTR ||
	    pMechanism->ulParameterLen != sizeof(CK_RSA_AES_KEY_WRAP_PARAMS))
	{
		ERROR_MSG("pParameter must be of type CK_RSA_AES_KEY_WRAP_PARAMS");
		return CKR_ARGUMENTS_BAD;
	}

	CK_RSA_AES_KEY_WRAP_PARAMS_PTR params = (CK_RSA_AES_KEY_WRAP_PARAMS_PTR)pMechanism->pParameter;
	if (params->ulAESKeyBits != 128 && params->ulAESKeyBits != 192 && params->ulAESKeyBits != 256)
	{
		ERROR_MSG("length of the temporary AES key in bits can be only 128, 192 or 256");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->pOAEPParams == NULL_PTR)
	{
		ERROR_MSG("pOAEPParams must be of type CK_RSA_PKCS_OAEP_PARAMS");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->pOAEPParams->mgf < 1UL || params->pOAEPParams->mgf > 5UL)
	{
		ERROR_MSG("mgf not supported");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->pOAEPParams->source != CKZ_DATA_SPECIFIED)
	{
		ERROR_MSG("source must be CKZ_DATA_SPECIFIED");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->pOAEPParams->pSourceData != NULL)
	{
		ERROR_MSG("pSourceData must be NULL");
		return CKR_ARGUMENTS_BAD;
	}
	if (params->pOAEPParams->ulSourceDataLen != 0)
	{
		ERROR_MSG("ulSourceDataLen must be 0");
		return CKR_ARGUMENTS_BAD;
	}

	return CKR_OK;
}


