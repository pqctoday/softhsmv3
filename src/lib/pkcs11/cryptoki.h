/*
 * SoftHSMv3 — compatibility shim for PKCS#11 v3.2
 *
 * Defines the 5 platform macros required by pkcs11.h, then includes it.
 * All source files that previously included this header continue to work
 * without modification after the upgrade to PKCS#11 v3.2 CSD01 headers.
 *
 * Original cryptoki.h Copyright (c) 2017 SURFnet bv (BSD-2 License).
 * PKCS#11 v3.2 headers Copyright (c) OASIS Open 2016,2019,2024.
 */

#ifndef _CRYPTOKI_H
#define _CRYPTOKI_H

/* 1. CK_PTR: pointer indirection */
#define CK_PTR *

/* 2. CK_DECLARE_FUNCTION: importable function declaration */
#define CK_DECLARE_FUNCTION(returnType, name) returnType name

/* 3. CK_DECLARE_FUNCTION_POINTER: function pointer declaration */
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)

/* 4. CK_CALLBACK_FUNCTION: application callback pointer */
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

/* 5. NULL_PTR */
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#endif /* _CRYPTOKI_H */
