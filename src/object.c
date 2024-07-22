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

JANET_FN(p11_set_attribute_value,
         "(set-attribute-value session-obj obj-handle template)",
         "Modifies the value of one or more attributes of an object. "
         "Returns a `session-obj`, if successful.")
{
    janet_fixarity(argc, 3);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    CK_OBJECT_HANDLE obj_handle = (CK_OBJECT_HANDLE)janet_getnumber(argv, 1);
    JanetStruct template = janet_getstruct(argv, 2);

    CK_ULONG count = (CK_ULONG)janet_struct_length(template);
    CK_ATTRIBUTE_PTR p_template = janet_struct_to_p11_template(template);

    CK_RV rv;
    rv = obj->func_list->C_SetAttributeValue(obj->session, obj_handle, p_template, count);
    PKCS11_ASSERT(rv, "C_SetAttributeValue");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_find_objects_init,
         "(find-objects-init session-obj &opt template)",
         "Initializes a search for token and session objects that match a "
         "`template`. Find all objects if `template` is not provided. "
         "Returns a `session-obj`, if successful.")
{
    janet_arity(argc, 1, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());

    JanetStruct template;
    CK_ULONG count = 0;
    CK_ATTRIBUTE_PTR p_template = NULL_PTR;

    if (argc == 2) {
        template = janet_getstruct(argv, 1);
        count = (CK_ULONG)janet_struct_length(template);
        p_template = janet_struct_to_p11_template(template);
    }

    CK_RV rv;
    rv = obj->func_list->C_FindObjectsInit(obj->session, p_template, count);
    PKCS11_ASSERT(rv, "C_FindObjectsInit");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_find_objects,
         "(find-objects session-obj max-obj-count)",
         "Continues a search for token and session objects that match a "
         "`template`. Returns a list of `obj-handle`, if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    CK_ULONG max_obj_count = (CK_ULONG)janet_getnumber(argv, 1);
    CK_ULONG count = 0;

    CK_OBJECT_HANDLE_PTR obj_list = janet_smalloc(max_obj_count * sizeof(CK_OBJECT_HANDLE));
    CK_RV rv;
    rv = obj->func_list->C_FindObjects(obj->session, obj_list, max_obj_count, &count);
    PKCS11_ASSERT(rv, "C_FindObjects");

    Janet *tup = janet_tuple_begin(count);
    for (int i=0; i<count; i++) {
        tup[i] = janet_wrap_number(obj_list[i]);
    }

    janet_sfree(obj_list);

    return janet_wrap_tuple(janet_tuple_end(tup));
}

JANET_FN(p11_find_objects_final,
         "(find-objects-final session-obj)",
         "Terminates a search for token and session objects. "
         "Returns a `session-obj`, if successful.")
{
    janet_fixarity(argc, 1);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    CK_RV rv;
    rv = obj->func_list->C_FindObjectsFinal(obj->session);
    PKCS11_ASSERT(rv, "C_FindObjectsFinal");

    return janet_wrap_abstract(obj);
}

void submod_object(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("create-object", p11_create_object),
        JANET_REG("copy-object", p11_copy_object),
        JANET_REG("destroy-object", p11_destroy_object),
        JANET_REG("get-object-size", p11_get_object_size),
        JANET_REG("get-attribute-value", p11_get_attribute_value),
        JANET_REG("set-attribute-value", p11_set_attribute_value),
        JANET_REG("find-objects-init", p11_find_objects_init),
        JANET_REG("find-objects", p11_find_objects),
        JANET_REG("find-objects-final", p11_find_objects_final),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "pkcs11", cfuns);
}
