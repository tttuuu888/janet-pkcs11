/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "error.h"
#include "attribute.h"
#include "types.h"

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
    PKCS11_ASSERT(rv);

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
    PKCS11_ASSERT(rv);

    return janet_wrap_number((double)obj_handle2);
}

JANET_FN(p11_destroy_object,
         "(destroy-object session-obj obj-handle)",
         "Destroys an object.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    CK_OBJECT_HANDLE obj_handle = (CK_OBJECT_HANDLE)janet_getnumber(argv, 1);

    CK_RV rv;
    rv = obj->func_list->C_DestroyObject(obj->session, obj_handle);
    PKCS11_ASSERT(rv);

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
    PKCS11_ASSERT(rv);

    return janet_wrap_number((double)size);
}

/* From PKCS#11 doc: Note that the error codes CKR_ATTRIBUTE_SENSITIVE,
 * CKR_ATTRIBUTE_TYPE_INVALID, and CKR_BUFFER_TOO_SMALL do not denote true
 * errors for C_GetAttributeValue. */
static bool is_get_attribute_ok(CK_RV rv) {
    return rv == CKR_OK
        || rv == CKR_ATTRIBUTE_SENSITIVE
        || rv == CKR_ATTRIBUTE_TYPE_INVALID
        || rv == CKR_BUFFER_TOO_SMALL;
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
    /* Find the required buffer size of each attribute. */
    rv = obj->func_list->C_GetAttributeValue(obj->session, obj_handle, p_template, count);
    if (!is_get_attribute_ok(rv)) {
        PKCS11_ASSERT(rv);
    }

    /* Allocate a buffer for each available attribute. */
    bool has_template = false;
    for (int i=0; i<count; i++) {
        if (p_template[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
            continue;
        }
        p_template[i].pValue = janet_smalloc(p_template[i].ulValueLen);
        if (get_attribute_type(p_template[i].type) == P11_ATTR_TEMPLATE) {
            /* A nested template attribute (e.g. CKA_WRAP_TEMPLATE) is an array
             * of CK_ATTRIBUTE. Zeroing the buffer makes the inner pValue
             * pointers NULL_PTR, which prompts the token to report the inner
             * value sizes on the next call. */
            memset(p_template[i].pValue, 0, p_template[i].ulValueLen);
            has_template = true;
        }
    }

    /* Read the values. For a nested template attribute this fills in only the
     * inner attributes' type and required length. */
    rv = obj->func_list->C_GetAttributeValue(obj->session, obj_handle, p_template, count);
    if (!is_get_attribute_ok(rv)) {
        PKCS11_ASSERT(rv);
    }

    if (has_template) {
        /* Allocate a buffer for each inner attribute value. */
        for (int i=0; i<count; i++) {
            if (p_template[i].ulValueLen == CK_UNAVAILABLE_INFORMATION ||
                get_attribute_type(p_template[i].type) != P11_ATTR_TEMPLATE) {
                continue;
            }

            CK_ATTRIBUTE_PTR nested = (CK_ATTRIBUTE_PTR)p_template[i].pValue;
            int nested_count = p_template[i].ulValueLen / sizeof(CK_ATTRIBUTE);
            for (int j=0; j<nested_count; j++) {
                if (nested[j].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
                    continue;
                }

                nested[j].pValue = janet_smalloc(nested[j].ulValueLen);
            }
        }

        /* Read the inner attribute values. */
        rv = obj->func_list->C_GetAttributeValue(obj->session, obj_handle, p_template, count);
        if (!is_get_attribute_ok(rv)) {
            PKCS11_ASSERT(rv);
        }
    }

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
    PKCS11_ASSERT(rv);

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
    PKCS11_ASSERT(rv);

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
    PKCS11_ASSERT(rv);

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
    PKCS11_ASSERT(rv);

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
