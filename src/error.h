/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#ifndef PKCS11_ERROR_H
#define PKCS11_ERROR_H

#include "janet.h"

#define PKCS11_ASSERT(rval, desc)                   \
    if (rval != 0) {                                \
        janet_panicf("%s, rv:%s",                   \
                     desc, get_pkcs11_error(rval)); \
    }

const char* get_pkcs11_error(int error);

#endif /* PKCS11_ERROR_H */
