/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "error.h"
#include "attribute.h"

JANET_FN(p11_sign_init,
         "(sign-init session-obj mechanism key-handle)",
         "Initializes a signature operation. "
         "Returns a `session-obj`, if successful.")
{
    janet_fixarity(argc, 3);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct mechanism = janet_getstruct(argv, 1);
    CK_OBJECT_HANDLE key_handle = janet_getnumber(argv, 2);

    CK_MECHANISM_PTR p_mechanism = janet_struct_to_p11_mechanism(mechanism);

    CK_RV rv;
    rv = obj->func_list->C_SignInit(obj->session, p_mechanism, key_handle);
    PKCS11_ASSERT(rv, "C_SignInit");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_sign,
         "(sign session-obj data)",
         "Signs data in a single part. Returns a signature of the data in "
         "string, if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView data = janet_getbytes(argv, 1);

    CK_BYTE_PTR sign_data = NULL_PTR;
    CK_ULONG sign_data_len = 0;

    CK_RV rv;
    rv = obj->func_list->C_Sign(obj->session,
                                (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                sign_data, &sign_data_len);
    PKCS11_ASSERT(rv, "C_Sign");

    sign_data = janet_smalloc(sign_data_len);
    rv = obj->func_list->C_Sign(obj->session,
                                (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                sign_data, &sign_data_len);
    PKCS11_ASSERT(rv, "C_Sign");

    return janet_wrap_string(janet_string(sign_data, sign_data_len));
}

JANET_FN(p11_sign_update,
         "(sign-update session-obj data)",
         "Continues a multiple-part signature operation, processing another "
         "`data` part. Returns a `session-obj`, if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView data = janet_getbytes(argv, 1);

    CK_RV rv;
    rv = obj->func_list->C_SignUpdate(obj->session,
                                      (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len);
    PKCS11_ASSERT(rv, "C_SignUpdate");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_sign_final,
         "(sign-final session-obj)",
         "Finishes a multiple-part signature operation. "
         "Return a signature of the data in string, if successful.")
{
    janet_fixarity(argc, 1);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());

    CK_BYTE_PTR sign_data = NULL_PTR;
    CK_ULONG sign_data_len = 0;

    CK_RV rv;
    rv = obj->func_list->C_SignFinal(obj->session, sign_data, &sign_data_len);
    PKCS11_ASSERT(rv, "C_SignFinal");

    sign_data = janet_smalloc(sign_data_len);
    rv = obj->func_list->C_SignFinal(obj->session, sign_data, &sign_data_len);
    PKCS11_ASSERT(rv, "C_SignFinal");

    return janet_wrap_string(janet_string(sign_data, sign_data_len));
}

JANET_FN(p11_sign_recover_init,
         "(sign-recover-init session-obj mechanism key-handle)",
         "Initializes a signature operation, where the data can be recovered "
         "from the signature. Returns a `session-obj`, if successful.")
{
    janet_fixarity(argc, 3);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct mechanism = janet_getstruct(argv, 1);
    CK_OBJECT_HANDLE key_handle = janet_getnumber(argv, 2);

    CK_MECHANISM_PTR p_mechanism = janet_struct_to_p11_mechanism(mechanism);

    CK_RV rv;
    rv = obj->func_list->C_SignRecoverInit(obj->session, p_mechanism, key_handle);
    PKCS11_ASSERT(rv, "C_SignRecoverInit");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_sign_recover,
         "(sign-recover session-obj data)",
         "Signs data in a single operation, where the data can be recovered "
         "from the signature. Returns a signature of the data in string, if "
         "successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView data = janet_getbytes(argv, 1);

    CK_BYTE_PTR sign_data = NULL_PTR;
    CK_ULONG sign_data_len = 0;

    CK_RV rv;
    rv = obj->func_list->C_SignRecover(obj->session,
                                       (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                       sign_data, &sign_data_len);
    PKCS11_ASSERT(rv, "C_SignRecover");

    sign_data = janet_smalloc(sign_data_len);
    rv = obj->func_list->C_SignRecover(obj->session,
                                       (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                       sign_data, &sign_data_len);
    PKCS11_ASSERT(rv, "C_SignRecover");

    return janet_wrap_string(janet_string(sign_data, sign_data_len));
}

void submod_sign(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("sign-init", p11_sign_init),
        JANET_REG("sign", p11_sign),
        JANET_REG("sign-update", p11_sign_update),
        JANET_REG("sign-final", p11_sign_final),
        JANET_REG("sign-recover-init", p11_sign_recover_init),
        JANET_REG("sign-recover", p11_sign_recover),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "pkcs11", cfuns);
}
