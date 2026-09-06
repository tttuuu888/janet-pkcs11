/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#ifndef PKCS11_UTILS_H
#define PKCS11_UTILS_H

#include "janet.h"

#define IS_ARG_KEYWORD(n, keyword)                                  \
    (((argc >= (n+1)) &&                                            \
      (janet_cstrcmp(janet_getkeyword(argv, n), keyword) == 0)) ?   \
     1 : 0)

/* Strip blank characters and return as a Janet string */
Janet pkcs11_trim_stringv(const uint8_t *buf, int32_t len);

#endif /* PKCS11_UTILS_H */
