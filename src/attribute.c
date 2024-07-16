/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"

static void set_attribute(CK_ATTRIBUTE *attribute, const JanetKV *kv)
{
    Janet key = kv->key;
    Janet val = kv->value;

    CK_ATTRIBUTE_TYPE attr_type = (CK_ATTRIBUTE_TYPE)janet_unwrap_number(key);

    attribute->type = attr_type;
    JanetType jt = janet_type(val);
    switch(jt) {
        case JANET_NUMBER: {
            CK_ULONG *value = janet_smalloc(sizeof(CK_ULONG));
            *value = (CK_ULONG)janet_unwrap_number(val);

            attribute->pValue = (void*)value;
            attribute->ulValueLen = sizeof(CK_ULONG);
            break;
        }
        case JANET_BOOLEAN: {
            CK_BBOOL *value = janet_smalloc(sizeof(CK_BBOOL));
            *value = (CK_BBOOL)janet_unwrap_boolean(val);

            attribute->pValue = (void*)value;
            attribute->ulValueLen = sizeof(CK_BBOOL);
            break;
        }
        case JANET_STRING: {
            const uint8_t *jstr = janet_unwrap_string(val);
            int slen = janet_string_length(jstr);
            CK_BYTE_PTR *value = janet_smalloc(slen);
            memcpy(value, jstr, slen);

            attribute->pValue = (void*)value;
            attribute->ulValueLen = slen;
            break;
        }
        default:
            janet_panic("Invalid template value type.");
            break;
    }
}

CK_ATTRIBUTE_PTR janet_struct_to_p11_template(JanetStruct st)
{
    int32_t count = janet_struct_length(st);
    int32_t capacity = janet_struct_capacity(st);
    CK_ATTRIBUTE_PTR p_template = janet_smalloc(count * sizeof(CK_ATTRIBUTE));
    int index = 0;

    for (int i=0; i<capacity; i++) {
        const JanetKV *kv = st + i;

        if (janet_checktype(kv->key, JANET_NIL))
            continue;

        set_attribute(&p_template[index], kv);
        index++;
    }

    return p_template;
}
