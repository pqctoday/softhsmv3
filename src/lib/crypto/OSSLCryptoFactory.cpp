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
 OSSLCryptoFactory.cpp

 OpenSSL 3.x EVP-only cryptographic algorithm factory.
 Legacy algorithms (DES, DSA, DH, GOST, MD5) and ENGINE-based code have been
 removed. Remaining: RSA, ECDSA, ECDH, EdDSA, AES, SHA family, HMAC, CMAC.
 *****************************************************************************/

#include "config.h"
#include "MutexFactory.h"
#include "OSSLCryptoFactory.h"
#include "OSSLRNG.h"
#include "OSSLAES.h"
#include "OSSLSHA1.h"
#include "OSSLSHA224.h"
#include "OSSLSHA256.h"
#include "OSSLSHA384.h"
#include "OSSLSHA512.h"
#include "OSSLCMAC.h"
#include "OSSLHMAC.h"
#include "OSSLRSA.h"
#include "OSSLECDH.h"
#include "OSSLECDSA.h"
#include "OSSLEDDSA.h"
#include "OSSLMLDSA.h"
#include "OSSLSLHDSA.h"
#include "OSSLMLKEM.h"

#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// Constructor
OSSLCryptoFactory::OSSLCryptoFactory()
{
	// Initialise the one-and-only RNG
	rng = new OSSLRNG();
}

// Destructor
OSSLCryptoFactory::~OSSLCryptoFactory()
{
	// Destroy the one-and-only RNG
	delete rng;
}

// Return the one-and-only instance
OSSLCryptoFactory* OSSLCryptoFactory::i()
{
	if (!instance.get())
	{
		instance.reset(new OSSLCryptoFactory());
	}

	return instance.get();
}

// This will destroy the one-and-only instance.
void OSSLCryptoFactory::reset()
{
	instance.reset();
}

// Create a concrete instance of a symmetric algorithm
SymmetricAlgorithm* OSSLCryptoFactory::getSymmetricAlgorithm(SymAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case SymAlgo::AES:
			return new OSSLAES();
		default:
			break;
	}

	// No algorithm implementation is available
	ERROR_MSG("Unknown algorithm '%i'", algorithm);
	return NULL;
}

// Create a concrete instance of an asymmetric algorithm
AsymmetricAlgorithm* OSSLCryptoFactory::getAsymmetricAlgorithm(AsymAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case AsymAlgo::RSA:
			return new OSSLRSA();
		case AsymAlgo::ECDH:
			return new OSSLECDH();
		case AsymAlgo::ECDSA:
			return new OSSLECDSA();
		case AsymAlgo::EDDSA:
			return new OSSLEDDSA();
		case AsymAlgo::MLDSA:
			return new OSSLMLDSA();
		case AsymAlgo::SLHDSA:
			return new OSSLSLHDSA();
		case AsymAlgo::MLKEM:
			return new OSSLMLKEM();
		default:
			break;
	}

	// No algorithm implementation is available
	ERROR_MSG("Unknown algorithm '%i'", algorithm);
	return NULL;
}

// Create a concrete instance of a hash algorithm
HashAlgorithm* OSSLCryptoFactory::getHashAlgorithm(HashAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case HashAlgo::SHA1:
			return new OSSLSHA1();
		case HashAlgo::SHA224:
			return new OSSLSHA224();
		case HashAlgo::SHA256:
			return new OSSLSHA256();
		case HashAlgo::SHA384:
			return new OSSLSHA384();
		case HashAlgo::SHA512:
			return new OSSLSHA512();
		default:
			break;
	}

	// No algorithm implementation is available
	ERROR_MSG("Unknown algorithm '%i'", algorithm);
	return NULL;
}

// Create a concrete instance of a MAC algorithm
MacAlgorithm* OSSLCryptoFactory::getMacAlgorithm(MacAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case MacAlgo::HMAC_SHA1:
			return new OSSLHMACSHA1();
		case MacAlgo::HMAC_SHA224:
			return new OSSLHMACSHA224();
		case MacAlgo::HMAC_SHA256:
			return new OSSLHMACSHA256();
		case MacAlgo::HMAC_SHA384:
			return new OSSLHMACSHA384();
		case MacAlgo::HMAC_SHA512:
			return new OSSLHMACSHA512();
		case MacAlgo::CMAC_AES:
			return new OSSLCMACAES();
		default:
			break;
	}

	// No algorithm implementation is available
	ERROR_MSG("Unknown algorithm '%i'", algorithm);
	return NULL;
}

// Get the global RNG (may be a unique RNG per thread)
RNG* OSSLCryptoFactory::getRNG(RNGImpl::Type name /* = RNGImpl::Default */)
{
	if (name == RNGImpl::Default)
	{
		return rng;
	}
	else
	{
		// No RNG implementation is available
		ERROR_MSG("Unknown RNG '%i'", name);

		return NULL;
	}
}
