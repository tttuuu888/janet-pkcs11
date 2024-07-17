/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "error.h"
#include "attribute.h"

JANET_FN(p11_create_object,
         "(create-object session-obj template)",
         "Creates a new object. Returns `obj-handle`(number), if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct template = janet_getstruct(argv, 1);

    CK_ULONG count = (CK_ULONG)janet_struct_length(template);
    CK_ATTRIBUTE_PTR p_template = janet_struct_to_p11_template(template);
    CK_OBJECT_HANDLE obj_handle;

    CK_RV rv;
    rv = obj->func_list->C_CreateObject(obj->session, p_template, count, &obj_handle);
    PKCS11_ASSERT(rv, "C_CreateObject");

    return janet_wrap_number((double)obj_handle);
}

JANET_FN(p11_copy_object,
         "(copy-object session-obj obj-handle template)",
         "Copies an object. Returns new `obj-handle`(number), if successful.")
{
    janet_fixarity(argc, 3);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    CK_OBJECT_HANDLE obj_handle1 = (CK_OBJECT_HANDLE)janet_getnumber(argv, 1);
    JanetStruct template = janet_getstruct(argv, 2);

    CK_ULONG count = (CK_ULONG)janet_struct_length(template);
    CK_ATTRIBUTE_PTR p_template = janet_struct_to_p11_template(template);
    CK_OBJECT_HANDLE obj_handle2 = 0;

    CK_RV rv;
    rv = obj->func_list->C_CopyObject(obj->session, obj_handle1, p_template, count, &obj_handle2);
    PKCS11_ASSERT(rv, "C_CopyObject");

    return janet_wrap_number((double)obj_handle2);
}

JANET_FN(p11_destroy_object,
         "(destory-object session-obj obj-handle)",
         "Destroys an object.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    CK_OBJECT_HANDLE obj_handle = (CK_OBJECT_HANDLE)janet_getnumber(argv, 1);

    CK_RV rv;
    rv = obj->func_list->C_DestroyObject(obj->session, obj_handle);
    PKCS11_ASSERT(rv, "C_DestroyObject");

    return janet_wrap_nil();
}

JANET_FN(p11_get_object_size,
         "(get-object-size session-obj obj-handle)",
         "Returns the size of an object in bytes")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    CK_OBJECT_HANDLE obj_handle = (CK_OBJECT_HANDLE)janet_getnumber(argv, 1);

    CK_ULONG size = 0;
    CK_RV rv;
    rv = obj->func_list->C_GetObjectSize(obj->session, obj_handle, &size);
    PKCS11_ASSERT(rv, "C_GetObjectSize");

    return janet_wrap_number((double)size);
}

JANET_FN(p11_get_attribute_value,
         "(get-attribute-value session-obj obj-handle attr-list)",
         "Obtains the value of one or more attributes of an object. "
         "Returns a template struct, if successful.")
{
    janet_fixarity(argc, 3);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    CK_OBJECT_HANDLE obj_handle = (CK_OBJECT_HANDLE)janet_getnumber(argv, 1);
    JanetTuple tup = janet_gettuple(argv, 2);
    CK_ULONG count = (CK_ULONG)janet_tuple_length(tup);
    CK_ATTRIBUTE_PTR p_template = create_new_p11_template_from_janet_tuple(tup);

    CK_RV rv;
    rv = obj->func_list->C_GetAttributeValue(obj->session, obj_handle, p_template, count);
    PKCS11_ASSERT(rv, "C_GetAttributeValue");

    for (int i=0; i<count; i++) {
        p_template[i].pValue = janet_smalloc(p_template[i].ulValueLen);
    }

    rv = obj->func_list->C_GetAttributeValue(obj->session, obj_handle, p_template, count);
    PKCS11_ASSERT(rv, "C_GetAttributeValue");

    JanetStruct st = p11_template_to_janet_struct(p_template, count);

    return janet_wrap_struct(st);
}

void submod_object(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("create-object", p11_create_object),
        JANET_REG("copy-object", p11_copy_object),
        JANET_REG("destroy-object", p11_destroy_object),
        JANET_REG("get-object-size", p11_get_object_size),
        JANET_REG("get-attribute-value", p11_get_attribute_value),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
