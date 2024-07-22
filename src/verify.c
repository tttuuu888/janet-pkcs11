/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "error.h"
#include "attribute.h"

JANET_FN(p11_verify_init,
         "(verify-init session-obj mechanism key-handle)",
         "Initializes a verification operation. "
         "Returns a `session-obj`, if successful.")
{
    janet_fixarity(argc, 3);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct mechanism = janet_getstruct(argv, 1);
    CK_OBJECT_HANDLE key_handle = janet_getnumber(argv, 2);

    CK_MECHANISM_PTR p_mechanism = janet_struct_to_p11_mechanism(mechanism);

    CK_RV rv;
    rv = obj->func_list->C_VerifyInit(obj->session, p_mechanism, key_handle);
    PKCS11_ASSERT(rv, "C_VerifyInit");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_verify,
         "(verify session-obj data signature)",
         "Verifies a signature in a single-part operation. Returns a boolean, "
         "if successful.")
{
    janet_fixarity(argc, 3);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView data = janet_getbytes(argv, 1);
    JanetByteView sig = janet_getbytes(argv, 2);

    bool ret = false;
    CK_RV rv;
    rv = obj->func_list->C_Verify(obj->session,
                                  (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                  (CK_BYTE_PTR)sig.bytes, (CK_ULONG)sig.len);
    if (rv == CKR_OK) {
        ret = true;
    } else if (rv == CKR_SIGNATURE_INVALID) {
        ret = false;
    } else {
        PKCS11_ASSERT(rv, "C_Verify");
    }

    return janet_wrap_boolean(ret);
}

JANET_FN(p11_verify_update,
         "(verify-update session-obj data)",
         "Continues a multiple-part verification operation, processing another "
         "`data` part. Returns a `session-obj`, if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView data = janet_getbytes(argv, 1);

    CK_RV rv;
    rv = obj->func_list->C_VerifyUpdate(obj->session,
                                        (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len);
    PKCS11_ASSERT(rv, "C_VerifyUpdate");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_verify_final,
         "(verify-final session-obj signature)",
         "Finishes a multiple-part verification operation, checking the "
         "signature. Returns a boolean, if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView sig = janet_getbytes(argv, 1);

    bool ret = false;
    CK_RV rv;
    rv = obj->func_list->C_VerifyFinal(obj->session,
                                       (CK_BYTE_PTR)sig.bytes, (CK_ULONG)sig.len);
    if (rv == CKR_OK) {
        ret = true;
    } else if (rv == CKR_SIGNATURE_INVALID) {
        ret = false;
    } else {
        PKCS11_ASSERT(rv, "C_VerifyFinal");
    }

    return janet_wrap_boolean(ret);
}

JANET_FN(p11_verify_recover_init,
         "(verify-recover-init session-obj mechanism key-handle)",
         "Initializes a signature verification operation, where the data is "
         "recovered from the signature. Returns a `session-obj`, if successful.")
{
    janet_fixarity(argc, 3);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct mechanism = janet_getstruct(argv, 1);
    CK_OBJECT_HANDLE key_handle = janet_getnumber(argv, 2);

    CK_MECHANISM_PTR p_mechanism = janet_struct_to_p11_mechanism(mechanism);

    CK_RV rv;
    rv = obj->func_list->C_VerifyRecoverInit(obj->session, p_mechanism, key_handle);
    PKCS11_ASSERT(rv, "C_VerifyRecoverInit");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_verify_recover,
         "(verify-recover session-obj signature)",
         "Verifies a signature in a single-part operation, where the data is "
         "recovered from the signature. If successful, resturns tuple of "
         "[boolean string], where string is a recovered data.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView sig = janet_getbytes(argv, 1);

    CK_BYTE_PTR recover_data = NULL_PTR;
    CK_ULONG recover_data_len = 0;

    bool ret;
    CK_RV rv;
    rv = obj->func_list->C_VerifyRecover(obj->session,
                                         (CK_BYTE_PTR)sig.bytes, (CK_ULONG)sig.len,
                                         recover_data, &recover_data_len);
    PKCS11_ASSERT(rv, "C_VerifyRecover");

    /*
     * NOTE: Even if the signature is invalid, C_VerifyRecover must return
     * CKR_OK when recover_data_len is 0.
     */

    recover_data = janet_smalloc(recover_data_len);
    rv = obj->func_list->C_VerifyRecover(obj->session,
                                         (CK_BYTE_PTR)sig.bytes, (CK_ULONG)sig.len,
                                         recover_data, &recover_data_len);
    if (rv == CKR_OK) {
        ret = true;
    } else if (rv == CKR_SIGNATURE_INVALID) {
        ret = false;
    } else {
        PKCS11_ASSERT(rv, "C_VerifyRecover");
    }

    Janet *tup = janet_tuple_begin(2);
    tup[0] = janet_wrap_boolean(ret);
    tup[1] = janet_wrap_string(janet_string(recover_data, recover_data_len));

    return janet_wrap_tuple(janet_tuple_end(tup));
}

void submod_verify(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("verify-init", p11_verify_init),
        JANET_REG("verify", p11_verify),
        JANET_REG("verify-update", p11_verify_update),
        JANET_REG("verify-final", p11_verify_final),
        JANET_REG("verify-recover-init", p11_verify_recover_init),
        JANET_REG("verify-recover", p11_verify_recover),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
