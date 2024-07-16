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
         "Creates a new object. Returns `OBJECT_HANDLE`(number), if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct template = janet_getstruct(argv, 1);

    CK_ULONG count = (CK_ULONG)janet_struct_length(template);
    CK_ATTRIBUTE_PTR p_template = janet_struct_to_p11_template(template);
    CK_OBJECT_HANDLE object_handle;

    CK_RV rv;
    rv = obj->func_list->C_CreateObject(obj->session, p_template, count, &object_handle);
    PKCS11_ASSERT(rv, "C_CreateObject");

    return janet_wrap_number((double)object_handle);
}

void submod_object(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("create-object", p11_create_object),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
