#include "define_wrapper.h"
#include <string.h>

EVP_PKEY *EVP_EC_gen_wrapped(const char *curve) {
    return EVP_EC_gen(curve);
}
