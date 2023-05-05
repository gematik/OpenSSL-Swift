#ifndef define_wrapper_h
#define define_wrapper_h
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

static const int EVP_PKEY_KEYPAIR_W = EVP_PKEY_KEYPAIR;
static const int EVP_PKEY_PUBLIC_KEY_W = EVP_PKEY_PUBLIC_KEY;
static const char* OSSL_PKEY_PARAM_GROUP_NAME_W = OSSL_PKEY_PARAM_GROUP_NAME;
static const char* OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT_W = OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT;
static const char* OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED_W = OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED;
static const char* OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED_W = OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED;
static const char* OSSL_PKEY_PARAM_PUB_KEY_W = OSSL_PKEY_PARAM_PUB_KEY;
static const char* OSSL_PKEY_PARAM_PRIV_KEY_W = OSSL_PKEY_PARAM_PRIV_KEY;
static const char* EVP_PKEY_CTX_NAME_EC = "EC"; // no constant defined

EVP_PKEY *EVP_EC_gen_wrapped(const char *curve);

#endif /* define_wrapper_h */
