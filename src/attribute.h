/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#ifndef ATTRIBUTE_H
#define ATTRIBUTE_H

#include "janet.h"
#include "cryptoki_compat/pkcs11.h"

CK_ATTRIBUTE_PTR janet_struct_to_p11_template(JanetStruct st);

#endif /* ATTRIBUTE_H */
