/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#ifndef ATTRIBUTE_H
#define ATTRIBUTE_H

#include "janet.h"
#include "cryptoki_compat/pkcs11.h"

JanetStruct p11_template_to_janet_struct(CK_ATTRIBUTE_PTR p_template, int count);
CK_ATTRIBUTE_PTR janet_struct_to_p11_template(JanetStruct st);
CK_ATTRIBUTE_PTR create_new_p11_template_from_janet_tuple(JanetTuple tup);

#endif /* ATTRIBUTE_H */
