/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#ifndef PKCS11_ERROR_H
#define PKCS11_ERROR_H

#include "janet.h"
#include "pkcs11_header/pkcs11.h"

#define PKCS11_ASSERT(rval)                         \
    do {                                            \
        if ((rval) != CKR_OK) {                     \
            pkcs11_panic_rv(rval);                  \
        }                                           \
    } while (0)

const char* get_pkcs11_error(CK_RV error);
JANET_NO_RETURN void pkcs11_panic_rv(CK_RV rv);

#endif /* PKCS11_ERROR_H */
