/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "types.h"

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

JanetStruct p11_template_to_janet_struct(CK_ATTRIBUTE_PTR p_template, int count)
{
    JanetTable *ret = janet_table(count);
    for (int i=0; i<count; i++) {
        p11_attr_type_t attr_type = get_attribute_type(p_template[i].type);
        switch (attr_type) {
            case P11_ATTR_BOOL: {
                bool value = (*((CK_BBOOL*)p_template[i].pValue)) == 0 ? 0 : 1;
                janet_table_put(ret,
                                janet_ckeywordv(p11_attr_type_to_string(p_template[i].type)),
                                janet_wrap_boolean(value));
                break;
            }
            case P11_ATTR_ULONG: {
                CK_ULONG value = *(CK_ULONG_PTR)p_template[i].pValue;
                janet_table_put(ret,
                                janet_ckeywordv(p11_attr_type_to_string(p_template[i].type)),
                                janet_wrap_number((double)value));
                break;
            }
            case P11_ATTR_DATE: {
                CK_DATE_PTR p_date = p_template[i].pValue;
                JanetTable *date = janet_table(3);
                janet_table_put(date, janet_ckeywordv("year"), janet_stringv(p_date->year, 4));
                janet_table_put(date, janet_ckeywordv("month"), janet_stringv(p_date->month, 2));
                janet_table_put(date, janet_ckeywordv("day"), janet_stringv(p_date->day, 2));

                janet_table_put(ret,
                                janet_ckeywordv(p11_attr_type_to_string(p_template[i].type)),
                                janet_wrap_struct(janet_table_to_struct(date)));
                break;
            }
            case P11_ATTR_BYTES:
            case P11_ATTR_STRING: {
                janet_table_put(ret,
                                janet_ckeywordv(p11_attr_type_to_string(p_template[i].type)),
                                janet_stringv((const uint8_t *)p_template[i].pValue, p_template[i].ulValueLen));
                break;
            }
            default: {
                janet_panicf("0x%d Attribute type is not found", attr_type);
            }
        }

    }

    return janet_table_to_struct(ret);
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

CK_ATTRIBUTE_PTR create_new_p11_template_from_janet_tuple(JanetTuple tup)
{
    int32_t count = janet_tuple_length(tup);
    CK_ATTRIBUTE_PTR p_template = janet_smalloc(count * sizeof(CK_ATTRIBUTE));
    for (int i=0; i<count; i++) {
        p_template[i].type = janet_getinteger64(tup, i);
        p_template[i].pValue = NULL_PTR;
        p_template[i].ulValueLen = 0;
    }

    return p_template;
}
