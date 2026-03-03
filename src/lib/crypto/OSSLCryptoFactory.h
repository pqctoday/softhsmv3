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
 OSSLCryptoFactory.h

 OpenSSL 3.x EVP-only cryptographic algorithm factory.
 ENGINE-based code, GOST, DES, DSA, DH, MD5, and FIPS 140-2 mode have been
 removed. Retained: RSA, ECDSA, ECDH, EdDSA, AES, SHA family, HMAC, CMAC.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLCRYPTOFACTORY_H
#define _SOFTHSM_V2_OSSLCRYPTOFACTORY_H

#include "config.h"
#include "CryptoFactory.h"
#include "SymmetricAlgorithm.h"
#include "AsymmetricAlgorithm.h"
#include "HashAlgorithm.h"
#include "MacAlgorithm.h"
#include "RNG.h"
#include <memory>

class OSSLCryptoFactory : public CryptoFactory
{
public:
	// Return the one-and-only instance
	static OSSLCryptoFactory* i();

	// This will destroy the one-and-only instance.
	static void reset();

	// Create a concrete instance of a symmetric algorithm
	virtual SymmetricAlgorithm* getSymmetricAlgorithm(SymAlgo::Type algorithm);

	// Create a concrete instance of an asymmetric algorithm
	virtual AsymmetricAlgorithm* getAsymmetricAlgorithm(AsymAlgo::Type algorithm);

	// Create a concrete instance of a hash algorithm
	virtual HashAlgorithm* getHashAlgorithm(HashAlgo::Type algorithm);

	// Create a concrete instance of a MAC algorithm
	virtual MacAlgorithm* getMacAlgorithm(MacAlgo::Type algorithm);

	// Get the global RNG (may be a unique RNG per thread)
	virtual RNG* getRNG(RNGImpl::Type name = RNGImpl::Default);

	// Destructor
	virtual ~OSSLCryptoFactory();

private:
	// Constructor
	OSSLCryptoFactory();

	// The one-and-only instance
	static std::unique_ptr<OSSLCryptoFactory> instance;

	// The one-and-only RNG instance
	RNG* rng;
};

#endif // !_SOFTHSM_V2_OSSLCRYPTOFACTORY_H
