/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#ifndef PKCS11_UTILS_H
#define PKCS11_UTILS_H

#define IS_ARG_KEYWORD(n, keyword)                                  \
    (((argc >= (n+1)) &&                                            \
      (janet_cstrcmp(janet_getkeyword(argv, n), keyword) == 0)) ?   \
     1 : 0)

#endif /* PKCS11_UTILS_H */
