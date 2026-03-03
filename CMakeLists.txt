cmake_minimum_required(VERSION 3.16)
project(softhsmv3 C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Build Options ----------------------------------------------------------

option(BUILD_TESTS "Compile tests along with libraries" OFF)
option(DISABLE_NON_PAGED_MEMORY "Disable non-paged memory for secure storage" OFF)
option(DISABLE_VISIBILITY "Disables and unsets -fvisibility=hidden" OFF)
option(ENABLE_PEDANTIC "Enable pedantic compile mode" OFF)
option(ENABLE_STRICT "Enable strict compile mode" ON)
option(ENABLE_STATIC "Build static libraries" ON)
option(WITH_OBJECTSTORE_BACKEND_DB "Build with object store backend database (SQLite3)" OFF)

# ECC and EdDSA are always enabled — required for PQC roadmap
set(WITH_ECC ON)
set(WITH_EDDSA ON)

# ---- Version ----------------------------------------------------------------

set(VERSION "3.0.0")
set(VERSION_MAJOR 3)
set(VERSION_MINOR 0)
set(VERSION_PATCH 0)

set(PACKAGE "softhsmv3")
set(PACKAGE_NAME "SoftHSMv3")
set(PACKAGE_VERSION "${VERSION}")
set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
set(PACKAGE_TARNAME "${PACKAGE}")
set(PACKAGE_BUGREPORT "https://github.com/pqctoday/softhsmv3/issues")
set(PACKAGE_URL "https://github.com/pqctoday/softhsmv3")

# ---- Paths ------------------------------------------------------------------

if(NOT DEFINED CMAKE_INSTALL_SYSCONFDIR)
    set(CMAKE_INSTALL_SYSCONFDIR "/etc")
endif()
if(NOT DEFINED CMAKE_INSTALL_LOCALSTATEDIR)
    set(CMAKE_INSTALL_LOCALSTATEDIR "/var")
endif()
include(GNUInstallDirs)

set(DEFAULT_LOG_LEVEL "INFO"
    CACHE STRING "The default log level")
set(DEFAULT_OBJECTSTORE_BACKEND "file"
    CACHE STRING "Default storage backend for token objects")
set(DEFAULT_PKCS11_LIB "${CMAKE_INSTALL_FULL_LIBDIR}/softhsm/libsofthsmv3${CMAKE_SHARED_LIBRARY_SUFFIX}"
    CACHE STRING "The default PKCS#11 library")
set(DEFAULT_SOFTHSM2_CONF "${CMAKE_INSTALL_FULL_SYSCONFDIR}/softhsmv3.conf"
    CACHE STRING "The default location of softhsmv3.conf")
set(DEFAULT_TOKENDIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/lib/softhsmv3/tokens/"
    CACHE STRING "The default location of the token directory")
set(DEFAULT_UMASK "0077"
    CACHE STRING "The default file mode creation mask")

set(MAX_PIN_LEN 255 CACHE STRING "Maximum PIN length")
set(MIN_PIN_LEN 4 CACHE STRING "Minimum PIN length")

# ---- Build Type -------------------------------------------------------------

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

message(STATUS "Build Configuration: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: C++${CMAKE_CXX_STANDARD}")

# ---- Crypto Backend: OpenSSL only -------------------------------------------

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
                      ${CMAKE_SOURCE_DIR}/cmake/modules)

# Require OpenSSL >= 3.5 for ML-DSA and ML-KEM EVP support
find_package(OpenSSL 3.5 REQUIRED)

if(OPENSSL_FOUND)
    message(STATUS "OpenSSL: ${OPENSSL_VERSION} at ${OPENSSL_INCLUDE_DIR}")
    set(CRYPTO_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CRYPTO_LIBS ${OPENSSL_LIBRARIES})
    set(WITH_OPENSSL 1)
else()
    message(FATAL_ERROR "OpenSSL >= 3.5 is required")
endif()

# ---- Compiler Options -------------------------------------------------------

include(CompilerOptions)
include(GenerateExportHeader)

# ---- Object Store -----------------------------------------------------------

if(WITH_OBJECTSTORE_BACKEND_DB)
    set(HAVE_OBJECTSTORE_BACKEND_DB 1)
    set(WITH_SQLITE3 ON)
    message(STATUS "Building with SQLite3 object store backend")
else()
    message(STATUS "Building with file object store backend")
endif()

# ---- Tests ------------------------------------------------------------------

enable_testing()

# ---- Config Header ----------------------------------------------------------

include_directories(${CMAKE_BINARY_DIR})

# ---- Subdirectories ---------------------------------------------------------

add_subdirectory(src)
