project(softhsm_crypto)

# OpenSSL-only backend. Botan, DES, DSA, DH, GOST, MD5 have been removed.
# ECC and EdDSA are always enabled.

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}
                 ${PROJECT_SOURCE_DIR}/../common
                 ${PROJECT_SOURCE_DIR}/../data_mgr
                 ${PROJECT_SOURCE_DIR}/../pkcs11
                 ${CRYPTO_INCLUDES}
                 )

set(SOURCES
    # Abstract base classes (retained algorithms)
    AESKey.cpp
    AsymmetricAlgorithm.cpp
    AsymmetricKeyPair.cpp
    CryptoFactory.cpp
    DerUtil.cpp
    ECParameters.cpp
    ECPrivateKey.cpp
    ECPublicKey.cpp
    EDPrivateKey.cpp
    EDPublicKey.cpp
    HashAlgorithm.cpp
    MacAlgorithm.cpp
    RSAParameters.cpp
    RSAPrivateKey.cpp
    RSAPublicKey.cpp
    SymmetricAlgorithm.cpp
    SymmetricKey.cpp

    # OpenSSL EVP implementations
    OSSLAES.cpp
    OSSLCMAC.cpp
    OSSLComp.cpp
    OSSLCryptoFactory.cpp
    OSSLECDH.cpp
    OSSLECDSA.cpp
    OSSLECKeyPair.cpp
    OSSLECPrivateKey.cpp
    OSSLECPublicKey.cpp
    OSSLEDDSA.cpp
    OSSLEDKeyPair.cpp
    OSSLEDPrivateKey.cpp
    OSSLEDPublicKey.cpp
    OSSLEVPCMacAlgorithm.cpp
    OSSLEVPHashAlgorithm.cpp
    OSSLEVPMacAlgorithm.cpp
    OSSLEVPSymmetricAlgorithm.cpp
    OSSLHMAC.cpp
    OSSLRNG.cpp
    OSSLRSA.cpp
    OSSLRSAKeyPair.cpp
    OSSLRSAPrivateKey.cpp
    OSSLRSAPublicKey.cpp
    OSSLSHA1.cpp
    OSSLSHA224.cpp
    OSSLSHA256.cpp
    OSSLSHA384.cpp
    OSSLSHA512.cpp
    OSSLUtil.cpp
    )

include_directories(${INCLUDE_DIRS})
add_library(${PROJECT_NAME} OBJECT ${SOURCES})
target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})

if(NOT CMAKE_VERSION VERSION_LESS "3.12")
    target_link_libraries(${PROJECT_NAME} ${CRYPTO_LIBS})
endif()

if(BUILD_TESTS)
    add_subdirectory(test)
endif(BUILD_TESTS)
