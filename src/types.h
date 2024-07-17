/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#ifndef PKCS11_TYPES_H
#define PKCS11_TYPES_H

typedef enum p11_attr_type {
    P11_ATTR_BOOL,
    P11_ATTR_ULONG,
    P11_ATTR_DATE,
    P11_ATTR_BYTES,
    P11_ATTR_STRING
} p11_attr_type_t;

p11_attr_type_t get_attribute_type(CK_ATTRIBUTE_TYPE type);
const char *p11_attr_type_to_string(unsigned long type);

#endif /* PKCS11_TYPES_H */
